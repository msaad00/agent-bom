"""Slack connector — discover installed apps and bots in a workspace.

Uses Slack Web API with a bot token.
Env var: SLACK_BOT_TOKEN.

Note: This is separate from integrations/slack.py which only *sends* alerts.
This connector *reads* from the Slack API to discover AI agents/bots.
"""

from __future__ import annotations

import asyncio
import logging
import os

from agent_bom.http_client import create_client, request_with_retry
from agent_bom.models import Agent, AgentType, MCPServer, TransportType

from .base import ConnectorError, ConnectorHealthState, ConnectorStatus

logger = logging.getLogger(__name__)

_SLACK_API = "https://slack.com/api"


def _get_config(bot_token: str | None = None) -> str:
    """Resolve Slack bot token from args or env vars."""
    token = bot_token or os.environ.get("SLACK_BOT_TOKEN", "")
    if not token:
        raise ConnectorError("Slack bot token required. Set --slack-bot-token or SLACK_BOT_TOKEN env var.")
    return token


async def _discover_async(bot_token: str) -> tuple[list[Agent], list[str]]:
    """Async discovery of Slack apps and bots."""
    agents: list[Agent] = []
    warnings: list[str] = []
    headers = {"Authorization": f"Bearer {bot_token}"}

    async with create_client(timeout=30.0) as client:
        # 1. Get workspace info
        workspace_name = "unknown-workspace"
        resp = await request_with_retry(client, "GET", f"{_SLACK_API}/team.info", headers=headers)
        if resp and resp.status_code == 200:
            data = resp.json()
            if data.get("ok"):
                workspace_name = data.get("team", {}).get("name", workspace_name)
            else:
                warnings.append(f"Slack team.info: {data.get('error', 'unknown error')}")

        # 2. Discover bot users (installed apps that have bot users)
        cursor = None
        while True:
            params: dict[str, str] = {"limit": "200"}
            if cursor:
                params["cursor"] = cursor

            resp = await request_with_retry(client, "GET", f"{_SLACK_API}/users.list", headers=headers, params=params)
            if not resp or resp.status_code != 200:
                if resp:
                    warnings.append(f"Slack users.list: HTTP {resp.status_code}")
                break

            data = resp.json()
            if not data.get("ok"):
                warnings.append(f"Slack users.list: {data.get('error', 'unknown error')}")
                break

            for member in data.get("members", []):
                if not member.get("is_bot"):
                    continue
                if member.get("deleted"):
                    continue

                bot_name = member.get("real_name", member.get("name", "unknown-bot"))
                bot_id = member.get("id", "")
                profile = member.get("profile", {})
                app_id = profile.get("api_app_id", "")

                server = MCPServer(
                    name=app_id or bot_name,
                    transport=TransportType.SSE,
                    url=f"https://api.slack.com/apps/{app_id}" if app_id else "",
                )
                agent = Agent(
                    name=f"slack-bot:{bot_name}",
                    agent_type=AgentType.CUSTOM,
                    config_path=f"slack://{workspace_name}",
                    source="slack",
                    mcp_servers=[server] if app_id else [],
                    metadata={
                        "bot_id": bot_id,
                        "app_id": app_id,
                        "type": "slack_bot",
                        "workspace": workspace_name,
                        "display_name": profile.get("display_name", ""),
                    },
                )
                agents.append(agent)

            # Pagination
            next_cursor = data.get("response_metadata", {}).get("next_cursor", "")
            if not next_cursor:
                break
            cursor = next_cursor

    return agents, warnings


def discover(
    bot_token: str | None = None,
    **_kwargs: object,
) -> tuple[list[Agent], list[str]]:
    """Discover installed Slack apps and bots in a workspace."""
    token = _get_config(bot_token)
    try:
        return asyncio.run(_discover_async(token))
    except ConnectorError:
        raise
    except Exception as e:
        raise ConnectorError(f"Slack discovery failed: {e}") from e


def health_check(
    bot_token: str | None = None,
    **_kwargs: object,
) -> ConnectorStatus:
    """Verify Slack API connectivity."""
    try:
        token = _get_config(bot_token)
    except ConnectorError as e:
        return ConnectorStatus(connector="slack", state=ConnectorHealthState.AUTH_FAILED, message=str(e))

    async def _check() -> ConnectorStatus:
        headers = {"Authorization": f"Bearer {token}"}
        async with create_client(timeout=10.0) as client:
            resp = await request_with_retry(client, "GET", f"{_SLACK_API}/auth.test", headers=headers)
            if resp is None:
                return ConnectorStatus(connector="slack", state=ConnectorHealthState.UNREACHABLE, message="No response")
            if resp.status_code != 200:
                return ConnectorStatus(connector="slack", state=ConnectorHealthState.UNREACHABLE, message=f"HTTP {resp.status_code}")
            data = resp.json()
            if not data.get("ok"):
                error = data.get("error", "unknown")
                if error in ("invalid_auth", "not_authed", "token_revoked"):
                    return ConnectorStatus(connector="slack", state=ConnectorHealthState.AUTH_FAILED, message=error)
                return ConnectorStatus(connector="slack", state=ConnectorHealthState.DEGRADED, message=error)
            return ConnectorStatus(
                connector="slack",
                state=ConnectorHealthState.HEALTHY,
                message="Connected",
                details={"team": data.get("team", ""), "user": data.get("user", "")},
            )

    try:
        return asyncio.run(_check())
    except Exception as e:
        return ConnectorStatus(connector="slack", state=ConnectorHealthState.UNREACHABLE, message=str(e))
