"""Attack flow graph builder — per-CVE blast radius chain for React Flow.

Converts BlastRadius JSON data (from to_json()) into @xyflow/react-compatible
nodes and edges, with filtering by CVE, severity, framework tag, and agent.

Also provides build_lateral_movement_flow() for visualizing cross-agent lateral
movement paths derived from context_graph_data (shared_servers, lateral_paths).
"""

from __future__ import annotations

from typing import Optional

# Column X positions for left-to-right layout
_X_CVE = 0
_X_PACKAGE = 350
_X_SERVER = 700
_X_AGENT = 1050
_X_CREDENTIAL = 1050
_X_TOOL = 1050
_Y_SPACING = 120
_Y_BRANCH_OFFSET = 60

# Lateral movement graph columns
_X_LM_AGENT_LEFT = 0
_X_LM_SERVER = 500
_X_LM_AGENT_RIGHT = 1000


def build_lateral_movement_flow(
    context_graph_data: dict,
    *,
    highlight_cross_poison: bool = True,
) -> dict:
    """Build a React Flow graph showing cross-agent lateral movement paths.

    Visualizes how agents are connected through shared MCP servers and which
    connections represent cross-agent poison risks (write+read tool pairs).

    Args:
        context_graph_data: Context graph dict with optional keys:
            - shared_servers: list of {name, agents, tools} dicts
            - lateral_paths: list of path lists (each a sequence of node names)
        highlight_cross_poison: If True, edges on shared servers with
            write+read tool pairs are styled as CRITICAL (red dashed).

    Returns:
        {"nodes": [...], "edges": [...], "stats": {...}}
    """
    shared_servers: list[dict] = context_graph_data.get("shared_servers", [])
    lateral_paths: list[list] = context_graph_data.get("lateral_paths", [])

    if not shared_servers and not lateral_paths:
        return {"nodes": [], "edges": [], "stats": {"total_agents": 0, "total_servers": 0, "lateral_edges": 0, "cross_poison_servers": 0}}

    nodes: list[dict] = []
    edges: list[dict] = []
    seen: set[str] = set()

    unique_agents: set[str] = set()
    unique_servers: set[str] = set()
    cross_poison_count = 0
    lateral_edge_count = 0

    y_agent_left = 0
    y_server = 0
    y_agent_right = 0

    # Track which side each agent was first placed on
    agent_side: dict[str, str] = {}

    def _add_agent_node(agent_nm: str) -> None:
        node_id = f"agent:{agent_nm}"
        if node_id in seen:
            return
        seen.add(node_id)
        unique_agents.add(agent_nm)
        nonlocal y_agent_left, y_agent_right
        # Alternate sides for visual clarity
        if agent_nm not in agent_side:
            if len(unique_agents) % 2 == 1:
                agent_side[agent_nm] = "left"
                y = y_agent_left
                y_agent_left += _Y_SPACING
                x = _X_LM_AGENT_LEFT
            else:
                agent_side[agent_nm] = "right"
                y = y_agent_right
                y_agent_right += _Y_SPACING
                x = _X_LM_AGENT_RIGHT
        else:
            x = _X_LM_AGENT_LEFT if agent_side[agent_nm] == "left" else _X_LM_AGENT_RIGHT
            y = 0  # already placed
            return
        nodes.append(
            {
                "id": node_id,
                "type": "attackFlowNode",
                "position": {"x": x, "y": y},
                "data": {"nodeType": "agent", "label": agent_nm, "agent_type": "", "status": ""},
            }
        )

    def _add_server_node(srv_nm: str, *, is_cross_poison: bool = False) -> None:
        node_id = f"srv:{srv_nm}"
        if node_id in seen:
            return
        seen.add(node_id)
        unique_servers.add(srv_nm)
        nonlocal y_server
        nodes.append(
            {
                "id": node_id,
                "type": "attackFlowNode",
                "position": {"x": _X_LM_SERVER, "y": y_server},
                "data": {
                    "nodeType": "server",
                    "label": srv_nm,
                    "is_cross_poison": is_cross_poison,
                },
            }
        )
        y_server += _Y_SPACING

    # Build from shared_servers
    for srv_info in shared_servers:
        srv_nm = srv_info.get("name", "") if isinstance(srv_info, dict) else str(srv_info)
        agents_on_srv: list[str] = srv_info.get("agents", []) if isinstance(srv_info, dict) else []
        tools: list[str] = srv_info.get("tools", []) if isinstance(srv_info, dict) else []

        # Detect cross-agent poison (write + read tool pair)
        has_write = any(
            kw in str(t).lower() for t in tools for kw in ("write", "insert", "store", "save", "create", "add", "index", "upsert", "embed")
        )
        has_read = any(
            kw in str(t).lower() for t in tools for kw in ("read", "search", "query", "retrieve", "fetch", "get", "lookup", "similarity")
        )
        is_cross_poison = highlight_cross_poison and has_write and has_read and len(agents_on_srv) >= 2
        if is_cross_poison:
            cross_poison_count += 1

        _add_server_node(srv_nm, is_cross_poison=is_cross_poison)
        for agent_nm in agents_on_srv:
            _add_agent_node(agent_nm)
            # Agent → Server edge
            edge_id = f"lm:agent:{agent_nm}->srv:{srv_nm}"
            if edge_id not in seen:
                seen.add(edge_id)
                lateral_edge_count += 1
                edge_style = (
                    {"stroke": "#dc2626", "strokeDasharray": "6,3", "strokeWidth": 2}
                    if is_cross_poison
                    else {"stroke": "#f97316", "strokeDasharray": "5,5"}
                )
                edges.append(
                    {
                        "id": edge_id,
                        "source": f"agent:{agent_nm}",
                        "target": f"srv:{srv_nm}",
                        "type": "smoothstep",
                        "animated": is_cross_poison,
                        "label": "cross-agent poison" if is_cross_poison else "shared",
                        "style": edge_style,
                        "data": {"edgeType": "cross_poison" if is_cross_poison else "lateral"},
                    }
                )

    # Build from explicit lateral_paths
    for path in lateral_paths:
        path_nodes = [(p if isinstance(p, str) else p.get("id", p.get("name", str(p)))) for p in path]
        for i in range(len(path_nodes) - 1):
            src, tgt = path_nodes[i], path_nodes[i + 1]
            # Infer type from prefix conventions
            src_id = src if ":" in src else f"agent:{src}"
            tgt_id = tgt if ":" in tgt else f"agent:{tgt}"
            for nid in (src_id, tgt_id):
                kind, nm = nid.split(":", 1) if ":" in nid else ("agent", nid)
                if kind == "agent":
                    _add_agent_node(nm)
                elif kind in ("srv", "server"):
                    _add_server_node(nm)
            edge_id = f"lm:{src_id}->{tgt_id}"
            if edge_id not in seen:
                seen.add(edge_id)
                lateral_edge_count += 1
                edges.append(
                    {
                        "id": edge_id,
                        "source": src_id,
                        "target": tgt_id,
                        "type": "smoothstep",
                        "animated": True,
                        "label": "lateral",
                        "style": {"stroke": "#f97316", "strokeDasharray": "5,5"},
                        "data": {"edgeType": "lateral"},
                    }
                )

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "total_agents": len(unique_agents),
            "total_servers": len(unique_servers),
            "lateral_edges": lateral_edge_count,
            "cross_poison_servers": cross_poison_count,
        },
    }


def build_attack_flow(
    blast_radius: list[dict],
    agents: list[dict],
    *,
    cve: Optional[str] = None,
    severity: Optional[str] = None,
    framework: Optional[str] = None,
    agent_name: Optional[str] = None,
    context_graph_data: Optional[dict] = None,
) -> dict:
    """Build React Flow nodes/edges from blast radius data.

    Args:
        blast_radius: The blast_radius list from to_json() output.
        agents: The agents list from to_json() output.
        cve: Filter to a specific CVE ID.
        severity: Filter by severity (critical/high/medium/low).
        framework: Filter by framework tag (e.g. "LLM05", "AML.T0010").
        agent_name: Filter to blast radii affecting a specific agent.
        context_graph_data: Optional context graph dict. When provided,
            lateral movement edges (orange dashed) are overlaid on the
            graph for shared servers with cross-agent poison risk.

    Returns:
        {"nodes": [...], "edges": [...], "stats": {...}}
    """
    # Apply filters
    filtered = list(blast_radius)
    if cve:
        filtered = [br for br in filtered if br.get("vulnerability_id") == cve]
    if severity:
        filtered = [br for br in filtered if br.get("severity", "").lower() == severity.lower()]
    if framework:
        filtered = [
            br
            for br in filtered
            if framework in br.get("owasp_tags", [])
            or framework in br.get("atlas_tags", [])
            or framework in br.get("nist_ai_rmf_tags", [])
            or framework in br.get("owasp_mcp_tags", [])
            or framework in br.get("owasp_agentic_tags", [])
            or framework in br.get("eu_ai_act_tags", [])
        ]
    if agent_name:
        filtered = [br for br in filtered if agent_name in br.get("affected_agents", [])]

    if not filtered:
        return {
            "nodes": [],
            "edges": [],
            "stats": _empty_stats(),
        }

    # Build agent lookup for metadata
    agent_lookup: dict[str, dict] = {}
    for a in agents:
        agent_lookup[a.get("name", "")] = a

    # Collect unique entities
    nodes: list[dict] = []
    edges: list[dict] = []
    seen_nodes: set[str] = set()

    # Track unique entities for stats
    unique_cves: set[str] = set()
    unique_packages: set[str] = set()
    unique_servers: set[str] = set()
    unique_agents: set[str] = set()
    unique_credentials: set[str] = set()
    unique_tools: set[str] = set()
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    # Y position trackers per column
    y_cve = 0
    y_package = 0
    y_server = 0
    y_agent = 0
    y_credential = 0
    y_tool = 0

    for br in filtered:
        vuln_id = br.get("vulnerability_id", "unknown")
        sev = br.get("severity", "low").lower()
        pkg_str = br.get("package", "unknown")
        ecosystem = br.get("ecosystem", "")

        # Parse package string "name@version"
        if "@" in pkg_str and not pkg_str.startswith("@"):
            pkg_name, pkg_version = pkg_str.rsplit("@", 1)
        elif pkg_str.startswith("@") and pkg_str.count("@") >= 2:
            # Scoped package like @scope/name@version
            at_idx = pkg_str.index("@", 1)
            pkg_name = pkg_str[:at_idx]
            pkg_version = pkg_str[at_idx + 1 :]
        else:
            pkg_name = pkg_str
            pkg_version = ""

        # CVE node
        cve_id = f"cve:{vuln_id}"
        if cve_id not in seen_nodes:
            seen_nodes.add(cve_id)
            unique_cves.add(vuln_id)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            nodes.append(
                {
                    "id": cve_id,
                    "type": "attackFlowNode",
                    "position": {"x": _X_CVE, "y": y_cve},
                    "data": {
                        "nodeType": "cve",
                        "label": vuln_id,
                        "severity": sev,
                        "cvss_score": br.get("cvss_score"),
                        "epss_score": br.get("epss_score"),
                        "is_kev": br.get("is_kev", False),
                        "risk_score": br.get("risk_score"),
                        "fixed_version": br.get("fixed_version"),
                        "owasp_tags": br.get("owasp_tags", []),
                        "atlas_tags": br.get("atlas_tags", []),
                        "nist_ai_rmf_tags": br.get("nist_ai_rmf_tags", []),
                        "owasp_mcp_tags": br.get("owasp_mcp_tags", []),
                        "owasp_agentic_tags": br.get("owasp_agentic_tags", []),
                        "eu_ai_act_tags": br.get("eu_ai_act_tags", []),
                    },
                }
            )
            y_cve += _Y_SPACING

        # Package node
        pkg_id = f"pkg:{pkg_str}"
        if pkg_id not in seen_nodes:
            seen_nodes.add(pkg_id)
            unique_packages.add(pkg_str)
            raw_version_provenance = br.get("package_version_provenance")
            version_provenance: dict = raw_version_provenance if isinstance(raw_version_provenance, dict) else {}
            nodes.append(
                {
                    "id": pkg_id,
                    "type": "attackFlowNode",
                    "position": {"x": _X_PACKAGE, "y": y_package},
                    "data": {
                        "nodeType": "package",
                        "label": pkg_name,
                        "version": pkg_version,
                        "ecosystem": ecosystem,
                        "version_provenance": version_provenance,
                        "version_source": version_provenance.get("version_source"),
                        "version_confidence": version_provenance.get("confidence"),
                    },
                }
            )
            y_package += _Y_SPACING

        # CVE → Package edge
        edge_cp = f"e:{cve_id}->{pkg_id}"
        if edge_cp not in seen_nodes:
            seen_nodes.add(edge_cp)
            edges.append(
                {
                    "id": edge_cp,
                    "source": cve_id,
                    "target": pkg_id,
                    "type": "smoothstep",
                    "animated": True,
                    "style": {"stroke": _severity_color(sev)},
                }
            )

        # Server nodes
        for srv_name in br.get("affected_servers", []):
            srv_id = f"srv:{srv_name}"
            if srv_id not in seen_nodes:
                seen_nodes.add(srv_id)
                unique_servers.add(srv_name)
                nodes.append(
                    {
                        "id": srv_id,
                        "type": "attackFlowNode",
                        "position": {"x": _X_SERVER, "y": y_server},
                        "data": {
                            "nodeType": "server",
                            "label": srv_name,
                        },
                    }
                )
                y_server += _Y_SPACING

            # Package → Server edge
            edge_ps = f"e:{pkg_id}->{srv_id}"
            if edge_ps not in seen_nodes:
                seen_nodes.add(edge_ps)
                edges.append(
                    {
                        "id": edge_ps,
                        "source": pkg_id,
                        "target": srv_id,
                        "type": "smoothstep",
                        "style": {"stroke": "#3b82f6"},
                    }
                )

        # Agent nodes
        for agent_nm in br.get("affected_agents", []):
            agent_id = f"agent:{agent_nm}"
            if agent_id not in seen_nodes:
                seen_nodes.add(agent_id)
                unique_agents.add(agent_nm)
                agent_meta = agent_lookup.get(agent_nm, {})
                nodes.append(
                    {
                        "id": agent_id,
                        "type": "attackFlowNode",
                        "position": {"x": _X_AGENT, "y": y_agent},
                        "data": {
                            "nodeType": "agent",
                            "label": agent_nm,
                            "agent_type": agent_meta.get("agent_type", ""),
                            "status": agent_meta.get("status", ""),
                        },
                    }
                )
                y_agent += _Y_SPACING

            # Server → Agent edges (connect each affected server to this agent)
            for srv_name in br.get("affected_servers", []):
                srv_id = f"srv:{srv_name}"
                edge_sa = f"e:{srv_id}->{agent_id}"
                if edge_sa not in seen_nodes:
                    seen_nodes.add(edge_sa)
                    edges.append(
                        {
                            "id": edge_sa,
                            "source": srv_id,
                            "target": agent_id,
                            "type": "smoothstep",
                            "style": {"stroke": "#10b981"},
                        }
                    )

        # Credential nodes
        for cred_name in br.get("exposed_credentials", []):
            cred_id = f"cred:{cred_name}"
            if cred_id not in seen_nodes:
                seen_nodes.add(cred_id)
                unique_credentials.add(cred_name)
                nodes.append(
                    {
                        "id": cred_id,
                        "type": "attackFlowNode",
                        "position": {"x": _X_CREDENTIAL, "y": y_credential + _Y_BRANCH_OFFSET},
                        "data": {
                            "nodeType": "credential",
                            "label": cred_name,
                        },
                    }
                )
                y_credential += _Y_SPACING

            # Server → Credential edges
            for srv_name in br.get("affected_servers", []):
                srv_id = f"srv:{srv_name}"
                edge_sc = f"e:{srv_id}->{cred_id}"
                if edge_sc not in seen_nodes:
                    seen_nodes.add(edge_sc)
                    edges.append(
                        {
                            "id": edge_sc,
                            "source": srv_id,
                            "target": cred_id,
                            "type": "smoothstep",
                            "animated": True,
                            "style": {"stroke": "#eab308"},
                        }
                    )

        # Tool nodes
        for tool_name in br.get("exposed_tools", br.get("reachable_tools", [])):
            tool_id = f"tool:{tool_name}"
            if tool_id not in seen_nodes:
                seen_nodes.add(tool_id)
                unique_tools.add(tool_name)
                nodes.append(
                    {
                        "id": tool_id,
                        "type": "attackFlowNode",
                        "position": {"x": _X_TOOL, "y": y_tool + _Y_BRANCH_OFFSET * 2},
                        "data": {
                            "nodeType": "tool",
                            "label": tool_name,
                        },
                    }
                )
                y_tool += int(_Y_SPACING * 0.8)

            # Server → Tool edges
            for srv_name in br.get("affected_servers", []):
                srv_id = f"srv:{srv_name}"
                edge_st = f"e:{srv_id}->{tool_id}"
                if edge_st not in seen_nodes:
                    seen_nodes.add(edge_st)
                    edges.append(
                        {
                            "id": edge_st,
                            "source": srv_id,
                            "target": tool_id,
                            "type": "smoothstep",
                            "style": {"stroke": "#a855f7"},
                        }
                    )

    # Overlay lateral movement edges from context graph (orange dashed)
    lm_stats: dict = {}
    if context_graph_data:
        lm = build_lateral_movement_flow(context_graph_data)
        lm_stats = lm.get("stats", {})
        # Add lateral edges (always new — prefixed with "lm:")
        for edge in lm["edges"]:
            if edge["id"] not in seen_nodes:
                seen_nodes.add(edge["id"])
                edges.append(edge)
        # Add agent/server nodes not yet present in the blast radius graph
        for node in lm["nodes"]:
            if node["id"] not in seen_nodes:
                seen_nodes.add(node["id"])
                nodes.append(node)

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "total_cves": len(unique_cves),
            "total_packages": len(unique_packages),
            "total_servers": len(unique_servers),
            "total_agents": len(unique_agents),
            "total_credentials": len(unique_credentials),
            "total_tools": len(unique_tools),
            "severity_counts": severity_counts,
            "lateral_edges": lm_stats.get("lateral_edges", 0),
            "cross_poison_servers": lm_stats.get("cross_poison_servers", 0),
        },
    }


def _severity_color(severity: str) -> str:
    """Return a hex color for the severity level."""
    return {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#eab308",
        "low": "#3b82f6",
    }.get(severity.lower(), "#71717a")


def _empty_stats() -> dict:
    """Return an empty stats dict."""
    return {
        "total_cves": 0,
        "total_packages": 0,
        "total_servers": 0,
        "total_agents": 0,
        "total_credentials": 0,
        "total_tools": 0,
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    }
