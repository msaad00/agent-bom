"""Jira connector — discover AI agents from automation rules and installed apps.

Uses Jira REST API v3 with basic auth (email + API token).
Env vars: JIRA_URL, JIRA_USER, JIRA_API_TOKEN.
"""

from __future__ import annotations

import asyncio
import logging
import os

from agent_bom.http_client import create_client, request_with_retry
from agent_bom.models import Agent, AgentType, MCPServer, TransportType

from .base import ConnectorError, ConnectorHealthState, ConnectorStatus

logger = logging.getLogger(__name__)


def _get_config(
    jira_url: str | None = None,
    email: str | None = None,
    api_token: str | None = None,
) -> tuple[str, str, str]:
    """Resolve Jira config from args or env vars."""
    url = jira_url or os.environ.get("JIRA_URL", "")
    user = email or os.environ.get("JIRA_USER", "")
    token = api_token or os.environ.get("JIRA_API_TOKEN", "")
    if not url:
        raise ConnectorError("Jira URL required. Set --jira-url or JIRA_URL env var.")
    if not user or not token:
        raise ConnectorError("Jira credentials required. Set JIRA_USER and JIRA_API_TOKEN env vars.")
    return url.rstrip("/"), user, token


async def _discover_async(
    jira_url: str,
    email: str,
    api_token: str,
) -> tuple[list[Agent], list[str]]:
    """Async discovery of Jira AI agents."""
    agents: list[Agent] = []
    warnings: list[str] = []
    auth = (email, api_token)

    async with create_client(timeout=30.0) as client:
        # 1. Discover automation rules
        resp = await request_with_retry(
            client,
            "GET",
            f"{jira_url}/rest/api/3/workflow/rule/config",
            auth=auth,
        )
        if resp and resp.status_code == 200:
            try:
                rules = resp.json()
                rule_list = rules if isinstance(rules, list) else rules.get("values", [])
                for rule in rule_list:
                    name = rule.get("name", rule.get("id", "unknown-rule"))
                    agent = Agent(
                        name=f"jira-automation:{name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=f"{jira_url}/automation",
                        source="jira",
                        metadata={"rule_id": rule.get("id", ""), "type": "automation_rule"},
                    )
                    agents.append(agent)
            except Exception as e:
                warnings.append(f"Jira automation parse error: {e}")
        elif resp and resp.status_code == 403:
            warnings.append("Jira automation rules: insufficient permissions (403)")
        elif resp and resp.status_code != 404:
            warnings.append(f"Jira automation rules: HTTP {resp.status_code}")

        # 2. Discover installed Forge/Connect apps
        resp = await request_with_retry(
            client,
            "GET",
            f"{jira_url}/rest/api/3/app/installed",
            auth=auth,
        )
        if resp and resp.status_code == 200:
            try:
                apps_data = resp.json()
                app_list = apps_data if isinstance(apps_data, list) else apps_data.get("values", apps_data.get("apps", []))
                for app_info in app_list:
                    app_name = app_info.get("name", app_info.get("key", "unknown-app"))
                    app_key = app_info.get("key", "")
                    server = MCPServer(
                        name=app_key or app_name,
                        transport=TransportType.SSE,
                        url=app_info.get("links", {}).get("self", ""),
                    )
                    agent = Agent(
                        name=f"jira-app:{app_name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=f"{jira_url}/plugins",
                        source="jira",
                        mcp_servers=[server],
                        metadata={
                            "app_key": app_key,
                            "type": "installed_app",
                            "vendor": app_info.get("vendor", {}).get("name", ""),
                        },
                    )
                    agents.append(agent)
            except Exception as e:
                warnings.append(f"Jira apps parse error: {e}")
        elif resp and resp.status_code == 403:
            warnings.append("Jira installed apps: insufficient permissions (403)")
        elif resp and resp.status_code != 404:
            warnings.append(f"Jira installed apps: HTTP {resp.status_code}")

    return agents, warnings


def discover(
    jira_url: str | None = None,
    email: str | None = None,
    api_token: str | None = None,
    **_kwargs: object,
) -> tuple[list[Agent], list[str]]:
    """Discover AI agents from Jira automation rules and installed apps."""
    url, user, token = _get_config(jira_url, email, api_token)
    try:
        return asyncio.run(_discover_async(url, user, token))
    except ConnectorError:
        raise
    except Exception as e:
        raise ConnectorError(f"Jira discovery failed: {e}") from e


def health_check(
    jira_url: str | None = None,
    email: str | None = None,
    api_token: str | None = None,
    **_kwargs: object,
) -> ConnectorStatus:
    """Verify Jira API connectivity."""
    try:
        url, user, token = _get_config(jira_url, email, api_token)
    except ConnectorError as e:
        return ConnectorStatus(connector="jira", state=ConnectorHealthState.AUTH_FAILED, message=str(e))

    async def _check() -> ConnectorStatus:
        async with create_client(timeout=10.0) as client:
            resp = await request_with_retry(client, "GET", f"{url}/rest/api/3/serverInfo", auth=(user, token))
            if resp is None:
                return ConnectorStatus(connector="jira", state=ConnectorHealthState.UNREACHABLE, message="No response from Jira API")
            if resp.status_code == 401:
                return ConnectorStatus(connector="jira", state=ConnectorHealthState.AUTH_FAILED, message="Invalid credentials")
            if resp.status_code == 200:
                data = resp.json()
                return ConnectorStatus(
                    connector="jira",
                    state=ConnectorHealthState.HEALTHY,
                    message="Connected",
                    api_version=data.get("version", ""),
                )
            return ConnectorStatus(
                connector="jira",
                state=ConnectorHealthState.DEGRADED,
                message=f"HTTP {resp.status_code}",
            )

    try:
        return asyncio.run(_check())
    except Exception as e:
        return ConnectorStatus(connector="jira", state=ConnectorHealthState.UNREACHABLE, message=str(e))
