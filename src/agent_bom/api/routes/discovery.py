"""Agent discovery API routes.

Endpoints:
    GET /v1/agents                    list discovered agents
    GET /v1/agents/{agent_name}       agent detail with blast radius
    GET /v1/agents/{agent_name}/lifecycle  lifecycle graph (React Flow)
    GET /v1/agents/mesh               mesh topology (React Flow)
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.mcp_observation_store import MCPObservation
from agent_bom.api.models import JobStatus
from agent_bom.api.stores import _get_fleet_store, _get_mcp_observation_store, _get_store
from agent_bom.security import sanitize_error

router = APIRouter()
_logger = logging.getLogger(__name__)


def _tenant_id(request: Request) -> str:
    return getattr(request.state, "tenant_id", "default")


def _completed_jobs(tenant_id: str) -> list[Any]:
    return [job for job in _get_store().list_all(tenant_id=tenant_id) if job.status == JobStatus.DONE and job.result]


def _iter_report_servers(report: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    rows: list[tuple[str, dict[str, Any]]] = []
    for agent in report.get("agents", []):
        agent_name = str(agent.get("name") or agent.get("agent_name") or "").strip()
        for server in agent.get("mcp_servers", []) or []:
            if isinstance(server, dict):
                rows.append((agent_name, server))
        # Back-compat for older pushed reports and gateway discovery seed data.
        for server in agent.get("servers", []) or []:
            if isinstance(server, dict):
                rows.append((agent_name, server))
    return rows


def _build_scan_history_index(tenant_id: str) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for job in _completed_jobs(tenant_id):
        report = job.result or {}
        for report_agent_name, report_server in _iter_report_servers(report):
            server_name = str(report_server.get("name") or "").strip()
            if not report_agent_name or not server_name:
                continue
            key = (report_agent_name, server_name)
            record = index.setdefault(
                key,
                {
                    "scan_sources": set(),
                    "first_seen": "",
                    "last_seen": "",
                },
            )
            for source in report.get("scan_sources", []) or []:
                if source:
                    record["scan_sources"].add(str(source))
            created_at = str(job.created_at or "")
            completed_at = str(job.completed_at or created_at)
            if created_at and (not record["first_seen"] or created_at < record["first_seen"]):
                record["first_seen"] = created_at
            if completed_at and completed_at > record["last_seen"]:
                record["last_seen"] = completed_at

    return {
        key: {
            "present": True,
            "scan_sources": sorted(value["scan_sources"]),
            "first_seen": value["first_seen"] or None,
            "last_seen": value["last_seen"] or None,
        }
        for key, value in index.items()
    }


def _build_gateway_index(tenant_id: str) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for job in _completed_jobs(tenant_id):
        for agent_name, report_server in _iter_report_servers(job.result or {}):
            server_name = str(report_server.get("name") or "").strip()
            server_url = str(report_server.get("url") or "").strip()
            if not server_name or not server_url.startswith(("http://", "https://")):
                continue
            record = index.setdefault(
                (server_name, server_url),
                {
                    "gateway_registered": True,
                    "source_agents": set(),
                },
            )
            if agent_name:
                record["source_agents"].add(agent_name)
    return {
        key: {
            "gateway_registered": value["gateway_registered"],
            "source_agents": sorted(value["source_agents"]),
        }
        for key, value in index.items()
    }


def _serialize_agent(
    agent,
    *,
    fleet_agent: dict[str, Any] | None = None,
    scan_history_index: dict[tuple[str, str], dict[str, Any]] | None = None,
    gateway_index: dict[tuple[str, str], dict[str, Any]] | None = None,
    observation_index: dict[str, MCPObservation] | None = None,
) -> dict:
    payload = asdict(agent)
    payload["mcp_servers"] = []
    for server in agent.mcp_servers:
        server_payload = asdict(server)
        credential_names = list(getattr(server, "credential_names", []) or [])
        server_url = getattr(server, "url", None)
        auth_mode = getattr(server, "auth_mode", None)
        if auth_mode is None:
            if credential_names:
                auth_mode = "env-credentials"
            elif server_url and "@" in server_url:
                auth_mode = "url-embedded-credentials"
            elif server_url:
                auth_mode = "network-no-auth-observed"
            else:
                auth_mode = "local-stdio"
        has_credentials = getattr(server, "has_credentials", None)
        if has_credentials is None:
            has_credentials = bool(credential_names)

        server_payload["auth_mode"] = auth_mode
        server_payload["has_credentials"] = has_credentials
        server_payload["credential_env_vars"] = credential_names
        server_payload.setdefault("args", list(getattr(server, "args", []) or []))
        server_payload.setdefault("url", server_url)
        server_payload.setdefault("config_path", getattr(server, "config_path", None))
        server_payload.setdefault("security_warnings", list(getattr(server, "security_warnings", []) or []))
        observation_id = f"{agent.name}:{getattr(server, 'stable_id', server.name)}"
        stored_observation = (observation_index or {}).get(observation_id)
        scan_history = (scan_history_index or {}).get(
            (agent.name, server.name),
            {"present": False, "scan_sources": [], "first_seen": None, "last_seen": None},
        )
        gateway_state = (gateway_index or {}).get(
            (server.name, server_url or ""),
            {"gateway_registered": False, "source_agents": []},
        )
        observed_via = ["local_discovery"]
        observed_scopes = ["endpoint"]
        if scan_history["present"]:
            observed_via.append("scan_result")
            observed_scopes.append("scan")
        if fleet_agent is not None:
            observed_via.append("fleet_sync")
        if gateway_state["gateway_registered"]:
            observed_via.append("gateway_discovery")
            observed_scopes.append("gateway")
        if stored_observation is not None:
            observed_via = sorted(set(stored_observation.observed_via) | set(observed_via))
            observed_scopes = sorted(set(stored_observation.observed_scopes) | set(observed_scopes))
            scan_sources = sorted(set(stored_observation.scan_sources) | set(scan_history["scan_sources"]))
            source_agents = sorted(set(stored_observation.source_agents) | set(gateway_state["source_agents"]))
            configured_locally = stored_observation.configured_locally
            fleet_present = stored_observation.fleet_present or fleet_agent is not None
            gateway_registered = stored_observation.gateway_registered or gateway_state["gateway_registered"]
            runtime_observed = stored_observation.runtime_observed
            first_seen = stored_observation.first_seen or scan_history["first_seen"]
            last_seen = stored_observation.last_seen or (fleet_agent.get("last_discovery") if fleet_agent else scan_history["last_seen"])
            last_synced = stored_observation.last_synced or (fleet_agent.get("updated_at") if fleet_agent else None)
        else:
            scan_sources = scan_history["scan_sources"]
            source_agents = gateway_state["source_agents"]
            configured_locally = True
            fleet_present = fleet_agent is not None
            gateway_registered = gateway_state["gateway_registered"]
            runtime_observed = False
            first_seen = scan_history["first_seen"]
            last_seen = fleet_agent.get("last_discovery") if fleet_agent else scan_history["last_seen"]
            last_synced = fleet_agent.get("updated_at") if fleet_agent else None
        payload["mcp_servers"].append(server_payload)
        server_payload["provenance"] = {
            "observed_via": observed_via,
            "observed_scopes": observed_scopes,
            "scan_sources": scan_sources,
            "source_agents": source_agents,
            "configured_locally": configured_locally,
            "fleet_present": fleet_present,
            "gateway_registered": gateway_registered,
            # Runtime correlation for per-server MCP objects is not yet wired through
            # a canonical store. Keep this explicit instead of inferring from alert volume.
            "runtime_observed": runtime_observed,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "last_synced": last_synced,
        }
    return payload


def _observation_index(tenant_id: str) -> dict[str, MCPObservation]:
    return {row.observation_id: row for row in _get_mcp_observation_store().list_by_tenant(tenant_id)}


def _persist_agent_observations(
    tenant_id: str,
    agent: Any,
    *,
    fleet_agent: dict[str, Any] | None,
    scan_history_index: dict[tuple[str, str], dict[str, Any]],
    gateway_index: dict[tuple[str, str], dict[str, Any]],
) -> None:
    store = _get_mcp_observation_store()
    for server in agent.mcp_servers:
        server_url = getattr(server, "url", None)
        scan_history = scan_history_index.get(
            (agent.name, server.name),
            {"present": False, "scan_sources": [], "first_seen": None, "last_seen": None},
        )
        gateway_state = gateway_index.get(
            (server.name, server_url or ""),
            {"gateway_registered": False, "source_agents": []},
        )
        observed_via = ["local_discovery"]
        observed_scopes = ["endpoint"]
        if scan_history["present"]:
            observed_via.append("scan_result")
            observed_scopes.append("scan")
        if fleet_agent is not None:
            observed_via.append("fleet_sync")
        if gateway_state["gateway_registered"]:
            observed_via.append("gateway_discovery")
            observed_scopes.append("gateway")
        credential_names = list(getattr(server, "credential_names", []) or [])
        auth_mode = getattr(server, "auth_mode", None)
        if auth_mode is None:
            if credential_names:
                auth_mode = "env-credentials"
            elif server_url and "@" in server_url:
                auth_mode = "url-embedded-credentials"
            elif server_url:
                auth_mode = "network-no-auth-observed"
            else:
                auth_mode = "local-stdio"
        store.put(
            MCPObservation(
                tenant_id=tenant_id,
                observation_id=f"{agent.name}:{getattr(server, 'stable_id', server.name)}",
                server_stable_id=getattr(server, "stable_id", server.name),
                server_fingerprint=getattr(server, "fingerprint", ""),
                server_name=server.name,
                agent_name=agent.name,
                transport=getattr(getattr(server, "transport", ""), "value", getattr(server, "transport", "")) or "",
                url=server_url,
                auth_mode=auth_mode,
                command=getattr(server, "command", "") or "",
                args=list(getattr(server, "args", []) or []),
                config_path=getattr(server, "config_path", None),
                credential_env_vars=credential_names,
                security_warnings=list(getattr(server, "security_warnings", []) or []),
                observed_via=observed_via,
                observed_scopes=observed_scopes,
                scan_sources=scan_history["scan_sources"],
                source_agents=gateway_state["source_agents"],
                configured_locally=True,
                fleet_present=fleet_agent is not None,
                gateway_registered=gateway_state["gateway_registered"],
                runtime_observed=False,
                first_seen=scan_history["first_seen"],
                last_seen=fleet_agent.get("last_discovery") if fleet_agent else scan_history["last_seen"],
                last_synced=fleet_agent.get("updated_at") if fleet_agent else None,
            )
        )


@router.get("/v1/agents", tags=["discovery"])
async def list_agents(request: Request) -> dict:
    """Quick auto-discovery of local AI agent configs (Claude Desktop, Cursor, Windsurf...).
    No CVE scan — instant results for the UI sidebar.
    """
    try:
        from agent_bom.discovery import discover_all
        from agent_bom.parsers import extract_packages

        agents = discover_all()
        for agent in agents:
            for server in agent.mcp_servers:
                if not server.packages:
                    server.packages = extract_packages(server)
        tenant_id = _tenant_id(request)
        scan_history_index = _build_scan_history_index(tenant_id)
        gateway_index = _build_gateway_index(tenant_id)
        fleet_index = {item.name: item.model_dump() for item in _get_fleet_store().list_by_tenant(tenant_id)}
        for agent in agents:
            _persist_agent_observations(
                tenant_id,
                agent,
                fleet_agent=fleet_index.get(agent.name),
                scan_history_index=scan_history_index,
                gateway_index=gateway_index,
            )
        observation_index = _observation_index(tenant_id)

        return {
            "agents": [
                _serialize_agent(
                    a,
                    fleet_agent=fleet_index.get(a.name),
                    scan_history_index=scan_history_index,
                    gateway_index=gateway_index,
                    observation_index=observation_index,
                )
                for a in agents
            ],
            "count": len(agents),
            "warnings": [],
        }
    except Exception as exc:  # noqa: BLE001
        _logger.exception("Agent discovery failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc)) from exc


@router.get("/v1/agents/{agent_name}", tags=["discovery"])
async def get_agent_detail(request: Request, agent_name: str) -> dict:
    """Get detailed view of a single agent with cross-referenced scan data."""
    try:
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
        for job in _get_store().list_all(tenant_id=_tenant_id(request)):
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

        fleet_agent = None
        tenant_id = _tenant_id(request)
        for candidate in _get_fleet_store().list_by_tenant(tenant_id):
            if candidate.name == agent_name:
                fleet_agent = candidate.model_dump()
                break
        scan_history_index = _build_scan_history_index(tenant_id)
        gateway_index = _build_gateway_index(tenant_id)
        _persist_agent_observations(
            tenant_id,
            agent,
            fleet_agent=fleet_agent,
            scan_history_index=scan_history_index,
            gateway_index=gateway_index,
        )
        observation_index = _observation_index(tenant_id)

        return {
            "agent": _serialize_agent(
                agent,
                fleet_agent=fleet_agent,
                scan_history_index=scan_history_index,
                gateway_index=gateway_index,
                observation_index=observation_index,
            ),
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
            "fleet": fleet_agent,
        }
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        _logger.exception("Agent detail failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc)) from exc


@router.get("/v1/agents/{agent_name}/lifecycle", tags=["discovery"])
async def get_agent_lifecycle(request: Request, agent_name: str) -> dict:
    """Get React Flow nodes/edges for an agent's full lifecycle graph.

    Shows: Agent -> MCP Servers -> Tools/Credentials -> Packages -> CVEs
    """
    from agent_bom.output.attack_flow import _severity_color

    detail = await get_agent_detail(request, agent_name)
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
async def get_agent_mesh(request: Request) -> dict:
    """Get a ReactFlow-compatible mesh topology of all discovered agents.

    Shows agents, their MCP servers, tools, and vulnerability overlay
    as an interactive graph.
    """
    try:
        from agent_bom.discovery import discover_all
        from agent_bom.output.agent_mesh import build_agent_mesh
        from agent_bom.parsers import extract_packages

        agents = discover_all()
        for agent in agents:
            for server in agent.mcp_servers:
                if not server.packages:
                    server.packages = extract_packages(server)

        tenant_id = _tenant_id(request)
        scan_history_index = _build_scan_history_index(tenant_id)
        gateway_index = _build_gateway_index(tenant_id)
        fleet_index = {item.name: item.model_dump() for item in _get_fleet_store().list_by_tenant(tenant_id)}
        for agent in agents:
            _persist_agent_observations(
                tenant_id,
                agent,
                fleet_agent=fleet_index.get(agent.name),
                scan_history_index=scan_history_index,
                gateway_index=gateway_index,
            )
        observation_index = _observation_index(tenant_id)
        agents_data = [
            _serialize_agent(
                a,
                fleet_agent=fleet_index.get(a.name),
                scan_history_index=scan_history_index,
                gateway_index=gateway_index,
                observation_index=observation_index,
            )
            for a in agents
        ]

        # Gather blast radius from completed scans for vuln overlay
        all_blast: list[dict] = []
        for job in _get_store().list_all(tenant_id=_tenant_id(request)):
            if job.status == JobStatus.DONE and job.result:
                all_blast.extend(job.result.get("blast_radius", []))

        return build_agent_mesh(agents_data, all_blast)
    except Exception as exc:  # noqa: BLE001
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc)) from exc
