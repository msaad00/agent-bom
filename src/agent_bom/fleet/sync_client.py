"""Local discovery → control-plane fleet sync (#3471)."""

from __future__ import annotations

import os
from dataclasses import asdict
from typing import Any

from agent_bom.fleet.trust_scoring import compute_trust_score
from agent_bom.push import generate_source_id, push_json, sanitize_results


def _default_fleet_sync_url(raw: str | None) -> str:
    url = (raw or os.environ.get("AGENT_BOM_PUSH_URL") or "").strip()
    if not url:
        raise ValueError("Set --push-url or AGENT_BOM_PUSH_URL to the control-plane /v1/fleet/sync endpoint")
    if url.rstrip("/").endswith("/v1/fleet/sync"):
        return url
    return f"{url.rstrip('/')}/v1/fleet/sync"


def _agent_to_fleet_dict(agent: Any, *, source_id: str) -> dict[str, Any]:
    score, factors = compute_trust_score(agent)
    agent_type = agent.agent_type
    agent_type_value = agent_type.value if hasattr(agent_type, "value") else str(agent_type)
    mcp_servers: list[dict[str, Any]] = []
    for server in getattr(agent, "mcp_servers", []) or []:
        server_payload = asdict(server)
        server_payload.pop("config_path", None)
        server_payload["credential_names"] = list(getattr(server, "credential_names", []) or [])
        mcp_servers.append(server_payload)
    payload: dict[str, Any] = {
        "name": agent.name,
        "agent_type": agent_type_value,
        "source_id": source_id,
        "trust_score": score,
        "trust_factors": factors,
        "mcp_servers": mcp_servers,
    }
    canonical_id = str(getattr(agent, "canonical_id", "") or "").strip()
    if canonical_id:
        payload["canonical_id"] = canonical_id
    return payload


def build_fleet_sync_payload(agents: list[Any], *, source_id: str | None = None) -> dict[str, Any]:
    sid = (source_id or generate_source_id()).strip()
    return {
        "source_id": sid,
        "agents": [_agent_to_fleet_dict(agent, source_id=sid) for agent in agents],
    }


def run_fleet_sync(
    *,
    push_url: str | None = None,
    api_key: str | None = None,
    project_dir: str | None = None,
    source_id: str | None = None,
) -> dict[str, Any]:
    """Discover local MCP agents and push them to ``POST /v1/fleet/sync``."""
    from agent_bom.discovery import discover_all

    url = _default_fleet_sync_url(push_url)
    token = api_key if api_key is not None else os.environ.get("AGENT_BOM_PUSH_API_KEY")
    agents = discover_all(project_dir=project_dir)
    payload = sanitize_results(build_fleet_sync_payload(agents, source_id=source_id))
    response = push_json(url, payload, api_key=token)
    if response is None:
        raise RuntimeError(f"Fleet sync push failed for {url}")
    return {
        "discovered": len(agents),
        "push_url": url,
        **response,
    }
