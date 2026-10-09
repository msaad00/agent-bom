"""Agent discovery API routes.

Endpoints:
    GET /v1/agents                    list discovered agents
    GET /v1/agents/{agent_name}       agent detail with blast radius
    GET /v1/agents/{agent_name}/lifecycle  lifecycle graph (React Flow)
    GET /v1/agents/mesh               mesh topology (React Flow)
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable
from copy import deepcopy
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.agent_findings import current_agent_blast_rows, estate_reach_names
from agent_bom.api.mcp_observation_store import MCPObservation, agent_observation_id, merge_observations
from agent_bom.api.models import JobStatus
from agent_bom.api.read_models import AgentsResponse, DiscoveryProvidersResponse, documented
from agent_bom.api.stores import _get_fleet_store, _get_mcp_observation_store, _get_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.asset_provenance import agent_discovery_provenance, package_discovery_provenance, package_version_provenance
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.constants import is_credential_key
from agent_bom.core.severity import normalize_severity
from agent_bom.inventory import build_agents_from_inventory
from agent_bom.mcp_blocklist import sanitize_security_intelligence_entry
from agent_bom.security import (
    sanitize_command_args,
    sanitize_env_vars,
    sanitize_error,
    sanitize_security_warnings,
    sanitize_text,
    sanitize_url,
)

if TYPE_CHECKING:
    from agent_bom.models import Agent

router = APIRouter()
_logger = logging.getLogger(__name__)
_AGENTS_RESPONSE_CACHE_TTL_SECONDS = 30.0
_agents_response_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def _clear_agents_response_cache_for_tests() -> None:
    _agents_response_cache.clear()


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _discover_agents_with_demo_fallback() -> list[Any]:
    """Use curated agents in demo mode and host discovery in real deployments."""
    from agent_bom.demo_estate.bootstrap import demo_estate_enabled

    if not demo_estate_enabled():
        from agent_bom.discovery import discover_all

        return discover_all()

    from agent_bom.demo import DEMO_INVENTORY

    return build_agents_from_inventory(DEMO_INVENTORY, "agent-bom --demo")


def _host_agents_for_tenant(tenant_id: str) -> list[Any] | None:
    """Live host agents when this tenant may see them, else ``None``.

    The API host's own AI clients are not a tenant's estate. Live discovery is
    served only to the showcase tenant in demo mode, or when an operator bound
    this host to the tenant (the same fail-closed gate the scan pipeline
    enforces for ``discover_host``).
    ``None`` tells callers to serve the tenant's scanned estate instead.
    """
    from agent_bom.api.scan_boundary import require_host_discovery_for_tenant
    from agent_bom.demo_estate.bootstrap import SHOWCASE_TENANT, demo_estate_enabled
    from agent_bom.security import SecurityError

    if demo_estate_enabled():
        if tenant_id != SHOWCASE_TENANT:
            return None
    else:
        try:
            require_host_discovery_for_tenant(tenant_id)
        except SecurityError:
            return None
    return _discover_agents_with_demo_fallback()


def _scanned_estate_agents(tenant_id: str) -> list[dict[str, Any]]:
    from agent_bom.api.estate_agents import scanned_estate_agents

    jobs = [job for job in _get_store().list_all(tenant_id=tenant_id) if job.status == JobStatus.DONE and job.result]
    return scanned_estate_agents(jobs)


def _merge_strings(*values: list[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for group in values:
        for value in group:
            if value not in seen:
                seen.add(value)
                merged.append(value)
    return merged


def _merge_security_intelligence(*values: list[dict[str, object]]) -> list[dict[str, object]]:
    merged: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for group in values:
        for item in group:
            if not isinstance(item, dict):
                continue
            safe_item = sanitize_security_intelligence_entry(item)
            key = (str(safe_item.get("entry_id") or ""), str(safe_item.get("matched_value") or ""))
            if key in seen:
                continue
            seen.add(key)
            merged.append(safe_item)
    return merged


def _completed_jobs(tenant_id: str) -> list[Any]:
    return [job for job in _get_store().list_all(tenant_id=tenant_id) if job.status == JobStatus.DONE and job.result]


def _iter_report_servers(report: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    rows: list[tuple[str, str, dict[str, Any]]] = []
    for agent in report.get("agents", []):
        agent_id = str(agent.get("canonical_id") or agent.get("stable_id") or agent.get("id") or "")
        agent_name = str(agent.get("name") or agent.get("agent_name") or "").strip()
        for server in agent.get("mcp_servers", []) or []:
            if isinstance(server, dict):
                rows.append((agent_id, agent_name, server))
        # Back-compat for older pushed reports and gateway discovery seed data.
        for server in agent.get("servers", []) or []:
            if isinstance(server, dict):
                rows.append((agent_id, agent_name, server))
    return rows


def _build_scan_history_index(tenant_id: str) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for job in _completed_jobs(tenant_id):
        report = job.result or {}
        for report_agent_id, _label, report_server in _iter_report_servers(report):
            server_id = str(report_server.get("canonical_id") or report_server.get("stable_id") or report_server.get("id") or "")
            if not report_agent_id or not server_id:
                continue
            key = (report_agent_id, server_id)
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
        for agent_id, agent_name, report_server in _iter_report_servers(job.result or {}):
            server_id = str(report_server.get("canonical_id") or report_server.get("stable_id") or report_server.get("id") or "")
            server_url = str(report_server.get("url") or "").strip()
            if not agent_id or not server_id or not server_url.startswith(("http://", "https://")):
                continue
            record = index.setdefault(
                (agent_id, server_id),
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


def _observation_ids(agent: Any, server: Any, fleet_agent: dict[str, Any] | None = None) -> tuple[str, None]:
    # A legacy name-derived record cannot establish membership, even when the
    # name happens to be unique today. Keep it unbound until recollected.
    subject = str((fleet_agent or {}).get("agent_id") or agent.canonical_id)
    return agent_observation_id(subject, server.canonical_id), None


def _agent_count_by_class(agents: Iterable[Agent]) -> dict[str, int]:
    """Split discovered agents into AI clients vs background agents (additive).

    Excludes synthetic SBOM/image wrappers. Lets clients render one authoritative
    breakdown instead of each re-deriving from ``agent_type``.
    """
    from agent_bom.models import classify_agent_kind

    counts = {"client": 0, "background": 0}
    for agent in agents:
        kind = classify_agent_kind(agent)
        if kind in counts:
            counts[kind] += 1
    return counts


def _serialize_agent(
    agent: Agent,
    *,
    fleet_agent: dict[str, Any] | None = None,
    scan_history_index: dict[tuple[str, str], dict[str, Any]] | None = None,
    gateway_index: dict[tuple[str, str], dict[str, Any]] | None = None,
    observation_index: dict[str, MCPObservation] | None = None,
) -> dict:
    payload = asdict(agent)
    payload["canonical_id"] = agent.canonical_id
    payload["stable_id"] = agent.stable_id
    # Display-only class (AI client/host vs background/framework agent). Additive field; never renames agent_type or any existing key.
    from agent_bom.models import classify_agent_kind

    payload["agent_class"] = classify_agent_kind(agent)
    agent_provenance = agent_discovery_provenance(agent)
    payload["discovery_provenance"] = agent_provenance
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
        server_payload["command"] = sanitize_text(getattr(server, "command", ""), max_len=200)
        server_payload["env"] = sanitize_env_vars(dict(getattr(server, "env", {}) or {}))
        server_payload["credential_env_vars"] = credential_names
        server_payload["security_blocked"] = bool(getattr(server, "security_blocked", False))
        server_payload["args"] = sanitize_command_args(list(getattr(server, "args", []) or []))
        server_payload["url"] = sanitize_url(server_url)
        server_payload.setdefault("config_path", getattr(server, "config_path", None))
        server_payload["security_warnings"] = sanitize_security_warnings(list(getattr(server, "security_warnings", []) or []))
        server_payload["security_intelligence"] = _merge_security_intelligence(list(getattr(server, "security_intelligence", []) or []))
        for idx, package in enumerate(getattr(server, "packages", []) or []):
            if idx < len(server_payload.get("packages", []) or []):
                server_payload["packages"][idx]["version_provenance"] = package_version_provenance(
                    package,
                    inherited=agent_provenance,
                )
                server_payload["packages"][idx]["discovery_provenance"] = package_discovery_provenance(
                    package,
                    inherited=agent_provenance,
                )
        observation_id, legacy_observation_id = _observation_ids(agent, server, fleet_agent)
        stored_observation = (observation_index or {}).get(observation_id)
        if stored_observation is None and legacy_observation_id:
            stored_observation = (observation_index or {}).get(legacy_observation_id)
        scan_history = (scan_history_index or {}).get(
            (agent.canonical_id, server.canonical_id),
            {"present": False, "scan_sources": [], "first_seen": None, "last_seen": None},
        )
        gateway_state = (gateway_index or {}).get(
            (agent.canonical_id, server.canonical_id),
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
            server_payload["security_blocked"] = bool(server_payload["security_blocked"]) or stored_observation.security_blocked
            server_payload["security_warnings"] = _merge_strings(
                list(server_payload.get("security_warnings", []) or []),
                sanitize_security_warnings(stored_observation.security_warnings),
            )
            server_payload["security_intelligence"] = _merge_security_intelligence(
                list(server_payload.get("security_intelligence", []) or []),
                stored_observation.security_intelligence,
            )
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


def _live_observation_index(
    tenant_id: str,
    agents: list[Any],
    fleet_index: dict[str, dict[str, Any]],
    scan_history_index: dict[tuple[str, str], dict[str, Any]],
    gateway_index: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, MCPObservation]:
    """Stored observations with live discovery merged in memory only.

    Read routes never persist: stored rows stay owned by explicit writers
    (fleet sync, scans), so a GET cannot write into the caller's tenant.
    """
    index = _observation_index(tenant_id)
    for agent in agents:
        fleet_agent = fleet_index.get(getattr(agent, "canonical_id", ""))
        _overlay_agent_observations(tenant_id, agent, fleet_agent, scan_history_index, gateway_index, index)
    return index


def _overlay_agent_observations(
    tenant_id: str,
    agent: Any,
    fleet_agent: dict[str, Any] | None,
    scan_history_index: dict[tuple[str, str], dict[str, Any]],
    gateway_index: dict[tuple[str, str], dict[str, Any]],
    observation_index: dict[str, MCPObservation],
) -> None:
    for server in agent.mcp_servers:
        server_url = getattr(server, "url", None)
        scan_history = scan_history_index.get(
            (agent.canonical_id, server.canonical_id),
            {"present": False, "scan_sources": [], "first_seen": None, "last_seen": None},
        )
        gateway_state = gateway_index.get(
            (agent.canonical_id, server.canonical_id),
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
        observation_id, legacy_observation_id = _observation_ids(agent, server, fleet_agent)
        candidate = MCPObservation(
            tenant_id=tenant_id,
            observation_id=observation_id,
            server_stable_id=getattr(server, "stable_id", server.name),
            server_fingerprint=getattr(server, "fingerprint", ""),
            server_name=server.name,
            agent_name=agent.name,
            agent_id=str((fleet_agent or {}).get("agent_id") or ""),
            agent_canonical_id=agent.canonical_id,
            transport=getattr(getattr(server, "transport", ""), "value", getattr(server, "transport", "")) or "",
            url=sanitize_url(server_url),
            auth_mode=auth_mode,
            command=sanitize_text(getattr(server, "command", ""), max_len=200),
            args=sanitize_command_args(list(getattr(server, "args", []) or [])),
            config_path=getattr(server, "config_path", None),
            credential_env_vars=credential_names,
            security_blocked=bool(getattr(server, "security_blocked", False)),
            security_warnings=sanitize_security_warnings(list(getattr(server, "security_warnings", []) or [])),
            security_intelligence=[
                sanitize_security_intelligence_entry(item)
                for item in (getattr(server, "security_intelligence", []) or [])
                if isinstance(item, dict)
            ],
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
        existing = observation_index.get(observation_id)
        if existing is None and legacy_observation_id:
            existing = observation_index.get(legacy_observation_id)
        observation_index[observation_id] = merge_observations(existing, candidate)


def _fleet_identity_index(tenant_id: str) -> dict[str, dict[str, Any]]:
    fleet_groups: dict[str, list[Any]] = {}
    for item in _get_fleet_store().list_by_tenant(tenant_id):
        if item.canonical_id:
            fleet_groups.setdefault(item.canonical_id, []).append(item)
    return {key: rows[0].model_dump() for key, rows in fleet_groups.items() if len(rows) == 1}


def _build_agents_response(tenant_id: str) -> dict[str, Any]:
    from agent_bom.api.estate_agents import AGENT_COUNT_DEFINITION, count_agent_payloads_by_class
    from agent_bom.parsers import extract_packages

    host_agents = _host_agents_for_tenant(tenant_id)
    if host_agents is None:
        estate = _scanned_estate_agents(tenant_id)
        return {
            "scope": "scanned_estate",
            "source": (
                "Agents from this tenant's completed scans, one row per canonical agent identity "
                "(the same population as /v1/inventory). Live discovery of this API host's own "
                "AI-client configs is disabled unless an operator binds the host to this tenant."
            ),
            "count_definition": AGENT_COUNT_DEFINITION,
            "agents": estate,
            "count": len(estate),
            "count_by_class": count_agent_payloads_by_class(estate),
            "warnings": [],
        }
    agents = host_agents
    for agent in agents:
        for server in agent.mcp_servers:
            if not server.packages:
                server.packages = extract_packages(server)
    scan_history_index = _build_scan_history_index(tenant_id)
    gateway_index = _build_gateway_index(tenant_id)
    # Only unique canonical identities bind discovery to fleet state. Names
    # remain labels, including for legacy rows lacking identity evidence.
    fleet_index = _fleet_identity_index(tenant_id)
    observation_index = _live_observation_index(tenant_id, agents, fleet_index, scan_history_index, gateway_index)

    return {
        # Scope marker so callers never conflate this population with the
        # scanned-estate roll-up at /v1/inventory. This endpoint is live
        # local-disk discovery of AI-client configs on this host (no CVE scan);
        # /v1/inventory aggregates agents from completed scan jobs (the estate).
        "scope": "local_discovery",
        "source": (
            "Live local-disk discovery of AI-client agent configs on this host "
            "(no CVE scan). For scanned-estate agents aggregated from completed "
            "scan jobs, see /v1/inventory."
        ),
        "agents": [
            _serialize_agent(
                a,
                fleet_agent=fleet_index.get(getattr(a, "canonical_id", "")),
                scan_history_index=scan_history_index,
                gateway_index=gateway_index,
                observation_index=observation_index,
            )
            for a in agents
        ],
        "count": len(agents),
        "count_by_class": _agent_count_by_class(agents),
        "warnings": [],
    }


@router.get("/agents", **documented(AgentsResponse), tags=["discovery"])
async def list_agents(
    request: Request,
    refresh: bool = Query(False, description="Bypass the sidebar cache and perform live local discovery"),
) -> dict:
    """Quick auto-discovery of local AI agent configs (Claude Desktop, Cursor, Windsurf...).
    No CVE scan — instant results for the UI sidebar.
    """
    try:
        tenant_id = _tenant_id(request)
        now = time.monotonic()
        cached = _agents_response_cache.get(tenant_id)
        if not refresh and cached is not None and now - cached[0] <= _AGENTS_RESPONSE_CACHE_TTL_SECONDS:
            return deepcopy(cached[1])

        async with adaptive_backpressure("discovery"):
            response = await anyio.to_thread.run_sync(_build_agents_response, tenant_id)
        _agents_response_cache[tenant_id] = (now, deepcopy(response))
        return response
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except Exception as exc:  # noqa: BLE001
        _logger.warning("Agent discovery failed: %s", sanitize_text(sanitize_error(exc, generic=True)))
        raise HTTPException(status_code=500, detail=sanitize_error(exc, generic=True)) from exc


@router.get("/discovery/providers", **documented(DiscoveryProvidersResponse), tags=["discovery"])
def list_discovery_providers() -> dict:
    """Return registered discovery provider capability and trust contracts."""

    from agent_bom.cloud import provider_contracts

    return provider_contracts()


@router.get("/agents/mesh", tags=["discovery"], deprecated=True)
async def get_agent_mesh(request: Request) -> dict:
    """Get a ReactFlow-compatible mesh topology of all discovered agents.

    Shows agents, their MCP servers, tools, and vulnerability overlay
    as an interactive graph.

    Soft-deprecated: no UI/CLI/MCP product consumer (#3666 Phase 2).

    The synchronous discovery + store scans run in a worker thread so they
    never block the event loop.
    """
    try:
        return await anyio.to_thread.run_sync(_get_agent_mesh_impl, request)
    except Exception as exc:  # noqa: BLE001
        _logger.error("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc)) from exc


def _get_agent_mesh_impl(request: Request) -> dict:
    from agent_bom.output.agent_mesh import build_agent_mesh
    from agent_bom.parsers import extract_packages

    tenant_id = _tenant_id(request)
    host_agents = _host_agents_for_tenant(tenant_id)
    if host_agents is None:
        estate_blast: list[dict] = []
        for job in _get_store().list_all(tenant_id=tenant_id):
            if job.status == JobStatus.DONE and job.result:
                estate_blast.extend(job.result.get("blast_radius", []))
        return build_agent_mesh(_scanned_estate_agents(tenant_id), estate_blast)
    agents = host_agents
    for agent in agents:
        for server in agent.mcp_servers:
            if not server.packages:
                server.packages = extract_packages(server)

    scan_history_index = _build_scan_history_index(tenant_id)
    gateway_index = _build_gateway_index(tenant_id)
    fleet_index = _fleet_identity_index(tenant_id)
    observation_index = _live_observation_index(tenant_id, agents, fleet_index, scan_history_index, gateway_index)
    agents_data = [
        _serialize_agent(
            a,
            fleet_agent=fleet_index.get(getattr(a, "canonical_id", "")),
            scan_history_index=scan_history_index,
            gateway_index=gateway_index,
            observation_index=observation_index,
        )
        for a in agents
    ]

    # Gather blast radius from completed scans for vuln overlay.
    all_blast: list[dict] = []
    for job in _get_store().list_all(tenant_id=_tenant_id(request)):
        if job.status == JobStatus.DONE and job.result:
            all_blast.extend(job.result.get("blast_radius", []))

    return build_agent_mesh(agents_data, all_blast)


@router.get("/agents/{agent_name}", tags=["discovery"])
async def get_agent_detail(request: Request, agent_name: str) -> dict:
    """Get detailed view of a single agent with cross-referenced scan data.

    The synchronous discovery + store scans run in a worker thread so they
    never block the event loop.
    """
    try:
        return await anyio.to_thread.run_sync(_get_agent_detail_impl, request, agent_name)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        _logger.error("Agent detail failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc)) from exc


def _get_agent_detail_impl(request: Request, agent_name: str) -> dict:
    from agent_bom.parsers import extract_packages

    host_agents = _host_agents_for_tenant(_tenant_id(request))
    if host_agents is None:
        return _estate_agent_detail(request, agent_name)
    agents = host_agents
    matches = [a for a in agents if a.canonical_id == agent_name]
    if not matches:
        # Compatibility for display-name URLs: resolve the selection only;
        # evidence joins below still require the selected object's identity.
        matches = [a for a in agents if a.name == agent_name]
    if len(matches) > 1:
        raise HTTPException(status_code=409, detail="Ambiguous agent label; select its canonical ID")
    if not matches:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent = matches[0]

    for server in agent.mcp_servers:
        if not server.packages:
            server.packages = extract_packages(server)

    total_packages = sum(len(s.packages) for s in agent.mcp_servers)
    total_tools = sum(len(s.tools) for s in agent.mcp_servers)
    all_credentials: list[str] = []
    for s in agent.mcp_servers:
        all_credentials.extend(s.credential_names)

    agent_blast = current_agent_blast_rows(
        _get_store().list_all(tenant_id=_tenant_id(request)),
        agent_id=agent.canonical_id,
        credential_names=set(all_credentials),
        tool_names={tool.name for s in agent.mcp_servers for tool in s.tools},
        server_names={s.name for s in agent.mcp_servers},
    )

    # Every blast radius lands in exactly one bucket. Advisories with no CVSS
    # vector normalise to ``unknown``; without an explicit bucket they fell out
    # of the histogram entirely and the detail page rendered "N vulnerabilities"
    # beside a 0/0/0/0 strip labelled Clean.
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unrated": 0}
    for br in agent_blast:
        sev = normalize_severity(br.get("severity"))
        severity_counts[sev if sev in severity_counts else "unrated"] += 1

    tenant_id = _tenant_id(request)
    fleet_index = _fleet_identity_index(tenant_id)
    fleet_agent = fleet_index.get(agent.canonical_id)
    scan_history_index = _build_scan_history_index(tenant_id)
    gateway_index = _build_gateway_index(tenant_id)
    observation_index = _live_observation_index(tenant_id, [agent], fleet_index, scan_history_index, gateway_index)

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


def _estate_agent_detail(request: Request, agent_name: str) -> dict:
    """Agent detail from the tenant's scanned estate (host discovery disabled)."""
    from agent_bom.api.estate_agents import agent_identity_key

    tenant_id = _tenant_id(request)
    estate = _scanned_estate_agents(tenant_id)
    matches = [agent for agent in estate if agent_identity_key(agent) == agent_name]
    if not matches:
        matches = [agent for agent in estate if agent.get("name") == agent_name]
        identities = {agent_identity_key(agent) for agent in matches}
        if len(matches) > 1 and (len(identities) > 1 or None in identities):
            raise HTTPException(status_code=409, detail="Ambiguous agent label; select its canonical ID")
    if not matches:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent = matches[0]
    canonical_id = agent_identity_key(agent) or ""

    servers = [server for server in agent.get("mcp_servers") or [] if isinstance(server, dict)]
    credentials: list[str] = []
    for server in servers:
        for name in server.get("credential_env_vars") or []:
            if isinstance(name, str) and name not in credentials:
                credentials.append(name)
    agent_blast = current_agent_blast_rows(
        _get_store().list_all(tenant_id=tenant_id), agent_id=canonical_id, **estate_reach_names(servers, credentials)
    )
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unrated": 0}
    for br in agent_blast:
        sev = normalize_severity(br.get("severity"))
        severity_counts[sev if sev in severity_counts else "unrated"] += 1

    return {
        "agent": agent,
        "summary": {
            "total_servers": len(servers),
            "total_packages": sum(len(server.get("packages") or []) for server in servers),
            "total_tools": sum(len(server.get("tools") or []) for server in servers),
            "total_credentials": len(credentials),
            "total_vulnerabilities": len(agent_blast),
            "severity_breakdown": severity_counts,
        },
        "blast_radius": agent_blast,
        "credentials": credentials,
        "fleet": _fleet_identity_index(tenant_id).get(canonical_id),
    }


@router.get("/agents/{agent_name}/lifecycle", tags=["discovery"])
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
        cred_vars = [k for k in srv.get("env", {}) if is_credential_key(k)]
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
                            "version_provenance": pkg.get("version_provenance"),
                            "discovery_provenance": pkg.get("discovery_provenance"),
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
