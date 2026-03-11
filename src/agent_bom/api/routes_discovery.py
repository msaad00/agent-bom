"""Agent discovery and lifecycle graph endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from agent_bom.api.models import JobStatus
from agent_bom.api.stores import _get_store
from agent_bom.security import sanitize_error

router = APIRouter()
_logger = logging.getLogger(__name__)


@router.get("/v1/agents", tags=["discovery"])
async def list_agents() -> dict:
    """Quick auto-discovery of local AI agent configs (Claude Desktop, Cursor, Windsurf...).
    No CVE scan — instant results for the UI sidebar.
    """
    try:
        from dataclasses import asdict

        from agent_bom.discovery import discover_all
        from agent_bom.parsers import extract_packages

        agents = discover_all()
        for agent in agents:
            for server in agent.mcp_servers:
                if not server.packages:
                    server.packages = extract_packages(server)

        return {
            "agents": [asdict(a) for a in agents],
            "count": len(agents),
            "warnings": [],
        }
    except Exception as exc:  # noqa: BLE001
        _logger.exception("Agent discovery failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc)) from exc


@router.get("/v1/agents/{agent_name}", tags=["discovery"])
async def get_agent_detail(agent_name: str) -> dict:
    """Get detailed view of a single agent with cross-referenced scan data."""
    try:
        from dataclasses import asdict

        from agent_bom.discovery import discover_all
        from agent_bom.parsers import extract_packages

        agents = discover_all()
        agent = None
        for a in agents:
            if a.name == agent_name:
                agent = a
                break

        if agent is None:
            raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not found")

        for server in agent.mcp_servers:
            if not server.packages:
                server.packages = extract_packages(server)

        # Cross-reference blast radii from completed scans
        agent_blast: list[dict] = []
        for job in _get_store().list_all():
            if job.status != JobStatus.DONE or not job.result:
                continue
            for br in job.result.get("blast_radius", []):
                if agent_name in br.get("affected_agents", []):
                    agent_blast.append(br)

        total_packages = sum(len(s.packages) for s in agent.mcp_servers)
        total_tools = sum(len(s.tools) for s in agent.mcp_servers)
        all_credentials: list[str] = []
        for s in agent.mcp_servers:
            all_credentials.extend(s.credential_names)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for br in agent_blast:
            sev = (br.get("severity") or "").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "agent": asdict(agent),
            "summary": {
                "total_servers": len(agent.mcp_servers),
                "total_packages": total_packages,
                "total_tools": total_tools,
                "total_credentials": len(all_credentials),
                "total_vulnerabilities": len(agent_blast),
                "severity_breakdown": severity_counts,
            },
            "blast_radius": agent_blast,
            "credentials": all_credentials,
        }
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        _logger.exception("Agent detail failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc)) from exc


@router.get("/v1/agents/{agent_name}/lifecycle", tags=["discovery"])
async def get_agent_lifecycle(agent_name: str) -> dict:
    """Get React Flow nodes/edges for an agent's full lifecycle graph.

    Shows: Agent -> MCP Servers -> Tools/Credentials -> Packages -> CVEs
    """
    from agent_bom.output.attack_flow import _severity_color

    detail = await get_agent_detail(agent_name)
    agent_data = detail["agent"]

    nodes: list[dict] = []
    edges: list[dict] = []
    seen: set[str] = set()

    agent_id = f"agent:{agent_data['name']}"
    nodes.append(
        {
            "id": agent_id,
            "type": "lifecycleNode",
            "position": {"x": 0, "y": 200},
            "data": {
                "nodeType": "agent",
                "label": agent_data["name"],
                "agent_type": agent_data.get("agent_type", ""),
            },
        }
    )

    y_offset = 0
    for srv in agent_data.get("mcp_servers", []):
        srv_id = f"srv:{srv['name']}"
        nodes.append(
            {
                "id": srv_id,
                "type": "lifecycleNode",
                "position": {"x": 350, "y": y_offset},
                "data": {
                    "nodeType": "server",
                    "label": srv["name"],
                    "transport": srv.get("transport", "stdio"),
                    "package_count": len(srv.get("packages", [])),
                    "tool_count": len(srv.get("tools", [])),
                },
            }
        )
        edges.append(
            {
                "id": f"e:{agent_id}->{srv_id}",
                "source": agent_id,
                "target": srv_id,
                "type": "smoothstep",
                "animated": True,
                "style": {"stroke": "#10b981"},
            }
        )

        # Tools
        ty = y_offset - 40
        for tool in srv.get("tools", [])[:10]:
            tid = f"tool:{srv['name']}:{tool['name']}"
            if tid not in seen:
                seen.add(tid)
                nodes.append(
                    {
                        "id": tid,
                        "type": "lifecycleNode",
                        "position": {"x": 700, "y": ty},
                        "data": {"nodeType": "tool", "label": tool["name"], "description": tool.get("description", "")},
                    }
                )
                edges.append(
                    {
                        "id": f"e:{srv_id}->{tid}",
                        "source": srv_id,
                        "target": tid,
                        "type": "smoothstep",
                        "style": {"stroke": "#a855f7"},
                    }
                )
                ty += 50

        # Credentials
        cy = ty + 10
        env = srv.get("env", {})
        _sens = ["key", "token", "secret", "password", "credential", "auth"]
        cred_vars = [k for k in env if any(p in k.lower() for p in _sens)]
        for cred in cred_vars:
            cid = f"cred:{cred}"
            if cid not in seen:
                seen.add(cid)
                nodes.append(
                    {
                        "id": cid,
                        "type": "lifecycleNode",
                        "position": {"x": 700, "y": cy},
                        "data": {"nodeType": "credential", "label": cred},
                    }
                )
                edges.append(
                    {
                        "id": f"e:{srv_id}->{cid}",
                        "source": srv_id,
                        "target": cid,
                        "type": "smoothstep",
                        "animated": True,
                        "style": {"stroke": "#eab308"},
                    }
                )
                cy += 50

        # Packages
        py_ = y_offset
        for pkg in srv.get("packages", []):
            pkg_key = f"{pkg['name']}@{pkg.get('version', '')}"
            pid = f"pkg:{pkg_key}"
            if pid not in seen:
                seen.add(pid)
                vulns = pkg.get("vulnerabilities", [])
                nodes.append(
                    {
                        "id": pid,
                        "type": "lifecycleNode",
                        "position": {"x": 1050, "y": py_},
                        "data": {
                            "nodeType": "package",
                            "label": pkg["name"],
                            "version": pkg.get("version", ""),
                            "ecosystem": pkg.get("ecosystem", ""),
                            "vuln_count": len(vulns),
                        },
                    }
                )
                edges.append(
                    {
                        "id": f"e:{srv_id}->{pid}",
                        "source": srv_id,
                        "target": pid,
                        "type": "smoothstep",
                        "style": {"stroke": "#3b82f6"},
                    }
                )

                # CVEs
                vy = py_
                for vuln in vulns:
                    vid = vuln.get("id", "")
                    cvid = f"cve:{vid}"
                    if cvid not in seen:
                        seen.add(cvid)
                        sev = vuln.get("severity", "low")
                        nodes.append(
                            {
                                "id": cvid,
                                "type": "lifecycleNode",
                                "position": {"x": 1400, "y": vy},
                                "data": {
                                    "nodeType": "cve",
                                    "label": vid,
                                    "severity": sev,
                                    "cvss_score": vuln.get("cvss_score"),
                                    "fixed_version": vuln.get("fixed_version"),
                                },
                            }
                        )
                        edges.append(
                            {
                                "id": f"e:{pid}->{cvid}",
                                "source": pid,
                                "target": cvid,
                                "type": "smoothstep",
                                "animated": True,
                                "style": {"stroke": _severity_color(sev)},
                            }
                        )
                        vy += 70
                py_ += max(len(vulns) * 70, 60)

        y_offset = max(y_offset + 180, py_)

    return {"nodes": nodes, "edges": edges, "stats": detail["summary"]}


@router.get("/v1/agents/mesh", tags=["discovery"])
async def get_agent_mesh() -> dict:
    """Get a ReactFlow-compatible mesh topology of all discovered agents."""
    try:
        from dataclasses import asdict

        from agent_bom.discovery import discover_all
        from agent_bom.output.agent_mesh import build_agent_mesh
        from agent_bom.parsers import extract_packages

        agents = discover_all()
        for agent in agents:
            for server in agent.mcp_servers:
                if not server.packages:
                    server.packages = extract_packages(server)

        agents_data = [asdict(a) for a in agents]

        all_blast: list[dict] = []
        for job in _get_store().list_all():
            if job.status == JobStatus.DONE and job.result:
                all_blast.extend(job.result.get("blast_radius", []))

        return build_agent_mesh(agents_data, all_blast)
    except Exception as exc:  # noqa: BLE001
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc)) from exc
