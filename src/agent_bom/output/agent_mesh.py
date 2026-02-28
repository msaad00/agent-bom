"""Agent mesh graph builder — ReactFlow-compatible nodes and edges for multi-agent topology."""

from __future__ import annotations


def _vuln_color(count: int) -> str:
    """Color based on vulnerability count."""
    if count == 0:
        return "#10b981"  # green
    if count <= 3:
        return "#eab308"  # yellow
    if count <= 8:
        return "#f97316"  # orange
    return "#ef4444"  # red


def build_agent_mesh(agents_data: list[dict], blast_radius: list[dict] | None = None) -> dict:
    """Build ReactFlow nodes/edges for a multi-agent mesh topology.

    agents_data: list of agent dicts (from discovery or scan results)
    blast_radius: optional blast radius entries for vulnerability overlay

    Returns: {"nodes": [...], "edges": [...], "stats": {...}}
    """
    nodes = []
    edges = []
    seen_servers: dict[str, str] = {}  # server_name -> node_id (for shared server merging)

    # Build vuln count per package from blast radius
    pkg_vulns: dict[str, int] = {}
    if blast_radius:
        for br in blast_radius:
            pkg = br.get("package", "")
            if pkg:
                pkg_vulns[pkg] = pkg_vulns.get(pkg, 0) + 1

    total_servers = 0
    total_packages = 0
    total_tools = 0
    total_credentials = 0
    total_vulns = 0

    agent_x = 0
    y_offset = 0

    for agent in agents_data:
        agent_name = agent.get("name", "unknown")
        servers = agent.get("mcp_servers", [])

        # Count agent-level vulns
        agent_vuln_count = 0
        for srv in servers:
            for pkg in srv.get("packages", []):
                agent_vuln_count += len(pkg.get("vulnerabilities", []))

        # Agent node
        agent_id = f"agent:{agent_name}"
        nodes.append(
            {
                "id": agent_id,
                "type": "meshNode",
                "position": {"x": agent_x, "y": y_offset},
                "data": {
                    "nodeType": "agent",
                    "label": agent_name,
                    "agent_type": agent.get("agent_type", ""),
                    "server_count": len(servers),
                    "vuln_count": agent_vuln_count,
                    "color": _vuln_color(agent_vuln_count),
                },
            }
        )

        srv_y = y_offset - ((len(servers) - 1) * 100) // 2

        for srv in servers:
            srv_name = srv.get("name", "unknown")
            total_servers += 1
            pkgs = srv.get("packages", [])
            tools = srv.get("tools", [])
            total_packages += len(pkgs)
            total_tools += len(tools)

            # Count credentials
            env = srv.get("env", {})
            sens = ["key", "token", "secret", "password", "credential", "auth"]
            creds = [k for k in env if any(p in k.lower() for p in sens)]
            total_credentials += len(creds)

            # Count vulns for this server
            srv_vuln_count = sum(len(p.get("vulnerabilities", [])) for p in pkgs)
            total_vulns += srv_vuln_count

            # Check if server is shared (same name across agents)
            if srv_name in seen_servers:
                # Just add edge from this agent to the existing server node
                existing_srv_id = seen_servers[srv_name]
                edges.append(
                    {
                        "id": f"e:{agent_id}->{existing_srv_id}",
                        "source": agent_id,
                        "target": existing_srv_id,
                        "type": "smoothstep",
                        "animated": True,
                        "style": {"stroke": "#10b981", "strokeDasharray": "5,5"},
                        "label": "shared",
                    }
                )
            else:
                srv_id = f"srv:{srv_name}"
                seen_servers[srv_name] = srv_id

                nodes.append(
                    {
                        "id": srv_id,
                        "type": "meshNode",
                        "position": {"x": agent_x + 400, "y": srv_y},
                        "data": {
                            "nodeType": "server",
                            "label": srv_name,
                            "transport": srv.get("transport", "stdio"),
                            "package_count": len(pkgs),
                            "tool_count": len(tools),
                            "credential_count": len(creds),
                            "vuln_count": srv_vuln_count,
                            "color": _vuln_color(srv_vuln_count),
                        },
                    }
                )

                edges.append(
                    {
                        "id": f"e:{agent_id}->{srv_id}",
                        "source": agent_id,
                        "target": srv_id,
                        "type": "smoothstep",
                        "animated": srv_vuln_count > 0,
                        "style": {"stroke": _vuln_color(srv_vuln_count)},
                    }
                )

                # Tool nodes
                tool_y = srv_y - 20
                for tool in tools[:8]:
                    tool_name = tool.get("name", "") if isinstance(tool, dict) else str(tool)
                    tool_id = f"tool:{srv_name}:{tool_name}"
                    nodes.append(
                        {
                            "id": tool_id,
                            "type": "meshNode",
                            "position": {"x": agent_x + 750, "y": tool_y},
                            "data": {
                                "nodeType": "tool",
                                "label": tool_name,
                            },
                        }
                    )
                    edges.append(
                        {
                            "id": f"e:{srv_id}->{tool_id}",
                            "source": srv_id,
                            "target": tool_id,
                            "type": "smoothstep",
                            "style": {"stroke": "#a855f7"},
                        }
                    )
                    tool_y += 40

            srv_y += 120

        y_offset += max(len(servers) * 120, 200)

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "total_agents": len(agents_data),
            "total_servers": total_servers,
            "total_packages": total_packages,
            "total_tools": total_tools,
            "total_credentials": total_credentials,
            "total_vulnerabilities": total_vulns,
        },
    }
