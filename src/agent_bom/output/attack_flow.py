"""Attack flow graph builder — per-CVE blast radius chain for React Flow.

Converts BlastRadius JSON data (from to_json()) into @xyflow/react-compatible
nodes and edges, with filtering by CVE, severity, framework tag, and agent.
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


def build_attack_flow(
    blast_radius: list[dict],
    agents: list[dict],
    *,
    cve: Optional[str] = None,
    severity: Optional[str] = None,
    framework: Optional[str] = None,
    agent_name: Optional[str] = None,
) -> dict:
    """Build React Flow nodes/edges from blast radius data.

    Args:
        blast_radius: The blast_radius list from to_json() output.
        agents: The agents list from to_json() output.
        cve: Filter to a specific CVE ID.
        severity: Filter by severity (critical/high/medium/low).
        framework: Filter by framework tag (e.g. "LLM05", "AML.T0010").
        agent_name: Filter to blast radii affecting a specific agent.

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
