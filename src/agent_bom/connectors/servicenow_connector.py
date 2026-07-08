"""ServiceNow connector — discover AI agents from Flow Designer and IntegrationHub.

Uses the ServiceNow REST API with an OAuth / API bearer token. Per policy,
agent-bom never uses passwords — only short-lived tokens. The token is
referenced from the OS environment only and never stored or logged.
Env vars: SERVICENOW_INSTANCE, AGENT_BOM_SERVICENOW_TOKEN.
"""

from __future__ import annotations

import asyncio
import logging
import os

from agent_bom.config import resolved_servicenow_instance_url
from agent_bom.http_client import create_client, request_with_retry
from agent_bom.models import Agent, AgentType, MCPServer, TransportType

from .base import CONNECTOR_HEALTH_TIMEOUT, ConnectorError, ConnectorHealthState, ConnectorStatus

logger = logging.getLogger(__name__)


def _bearer_headers(token: str) -> dict[str, str]:
    """Return Authorization headers for the ServiceNow OAuth/API bearer token."""
    return {"Authorization": f"Bearer {token}"}


def _get_config(
    instance_url: str | None = None,
    token: str | None = None,
) -> tuple[str, str]:
    """Resolve ServiceNow config from args or env vars."""
    url = instance_url or resolved_servicenow_instance_url()
    tok = token or os.environ.get("AGENT_BOM_SERVICENOW_TOKEN", "")
    if not url:
        raise ConnectorError("ServiceNow instance URL required. Set --servicenow-instance or SERVICENOW_INSTANCE env var.")
    if not tok:
        raise ConnectorError("ServiceNow token required. Set --servicenow-token or AGENT_BOM_SERVICENOW_TOKEN env var.")
    return url.rstrip("/"), tok


async def _discover_async(
    instance_url: str,
    token: str,
) -> tuple[list[Agent], list[str]]:
    """Async discovery of ServiceNow AI agents."""
    agents: list[Agent] = []
    warnings: list[str] = []
    headers = _bearer_headers(token)

    async with create_client() as client:
        # 1. Discover Flow Designer flows
        resp = await request_with_retry(
            client,
            "GET",
            f"{instance_url}/api/now/table/sys_hub_flow",
            headers=headers,
            params={"sysparm_limit": "200", "sysparm_fields": "sys_id,name,description,active,sys_scope.name"},
        )
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                flows = data.get("result", [])
                for flow in flows:
                    flow_name = flow.get("name", flow.get("sys_id", "unknown"))
                    is_active = flow.get("active", "true") == "true"
                    agent = Agent(
                        name=f"snow-flow:{flow_name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=f"{instance_url}/flow-designer",
                        source="servicenow",
                        metadata={
                            "sys_id": flow.get("sys_id", ""),
                            "type": "flow_designer",
                            "active": is_active,
                            "description": flow.get("description", ""),
                            "scope": flow.get("sys_scope.name", ""),
                        },
                    )
                    agents.append(agent)
            except Exception as e:
                warnings.append(f"ServiceNow flow parse error: {e}")
        elif resp and resp.status_code == 403:
            warnings.append("ServiceNow Flow Designer: insufficient permissions (403)")
        elif resp:
            warnings.append(f"ServiceNow Flow Designer: HTTP {resp.status_code}")

        # 2. Discover IntegrationHub spokes (action packs)
        resp = await request_with_retry(
            client,
            "GET",
            f"{instance_url}/api/now/table/sys_hub_action_type_definition",
            headers=headers,
            params={"sysparm_limit": "200", "sysparm_fields": "sys_id,name,description,sys_scope.name"},
        )
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                spokes = data.get("result", [])
                for spoke in spokes:
                    spoke_name = spoke.get("name", spoke.get("sys_id", "unknown"))
                    server = MCPServer(
                        name=spoke_name,
                        transport=TransportType.SSE,
                        url=f"{instance_url}/api/sn_ih",
                    )
                    agent = Agent(
                        name=f"snow-spoke:{spoke_name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=f"{instance_url}/integration-hub",
                        source="servicenow",
                        mcp_servers=[server],
                        metadata={
                            "sys_id": spoke.get("sys_id", ""),
                            "type": "integration_hub_spoke",
                            "scope": spoke.get("sys_scope.name", ""),
                        },
                    )
                    agents.append(agent)
            except Exception as e:
                warnings.append(f"ServiceNow spoke parse error: {e}")
        elif resp and resp.status_code == 403:
            warnings.append("ServiceNow IntegrationHub: insufficient permissions (403)")
        elif resp and resp.status_code != 404:
            warnings.append(f"ServiceNow IntegrationHub: HTTP {resp.status_code}")

    return agents, warnings


def discover(
    instance_url: str | None = None,
    token: str | None = None,
    **_kwargs: object,
) -> tuple[list[Agent], list[str]]:
    """Discover AI agents from ServiceNow Flow Designer and IntegrationHub."""
    url, tok = _get_config(instance_url, token)
    try:
        return asyncio.run(_discover_async(url, tok))
    except ConnectorError:
        raise
    except Exception as e:
        raise ConnectorError(f"ServiceNow discovery failed: {e}") from e


def health_check(
    instance_url: str | None = None,
    token: str | None = None,
    **_kwargs: object,
) -> ConnectorStatus:
    """Verify ServiceNow API connectivity."""
    try:
        url, tok = _get_config(instance_url, token)
    except ConnectorError as e:
        return ConnectorStatus(connector="servicenow", state=ConnectorHealthState.AUTH_FAILED, message=str(e))

    async def _check() -> ConnectorStatus:
        async with create_client(timeout=CONNECTOR_HEALTH_TIMEOUT) as client:
            resp = await request_with_retry(
                client,
                "GET",
                f"{url}/api/now/table/sys_properties",
                headers=_bearer_headers(tok),
                params={"sysparm_limit": "1"},
            )
            if resp is None:
                return ConnectorStatus(connector="servicenow", state=ConnectorHealthState.UNREACHABLE, message="No response")
            if resp.status_code == 401:
                return ConnectorStatus(connector="servicenow", state=ConnectorHealthState.AUTH_FAILED, message="Invalid credentials")
            if resp.status_code == 200:
                return ConnectorStatus(connector="servicenow", state=ConnectorHealthState.HEALTHY, message="Connected")
            return ConnectorStatus(connector="servicenow", state=ConnectorHealthState.DEGRADED, message=f"HTTP {resp.status_code}")

    try:
        return asyncio.run(_check())
    except Exception as e:
        return ConnectorStatus(connector="servicenow", state=ConnectorHealthState.UNREACHABLE, message=str(e))
