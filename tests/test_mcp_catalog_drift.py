"""Canonical MCP catalog drift guard (#3675 PR-E).

Registered ``@mcp.tool`` names must match ``_SERVER_CARD_TOOLS`` exactly so
server-card metadata, Docker MCP registry exports, and live tool listing stay
aligned.
"""

from __future__ import annotations

import asyncio

import pytest

from agent_bom.mcp_server_metadata import (
    registered_mcp_tool_decorator_names,
    server_card_tool_names,
)


def test_registered_mcp_tools_match_server_card_names() -> None:
    """Decorator names and server-card names must be the same set."""
    registered = registered_mcp_tool_decorator_names()
    card = server_card_tool_names()
    missing_from_card = sorted(registered - card)
    extra_in_card = sorted(card - registered)
    assert registered == card, (
        f"@mcp.tool names diverge from _SERVER_CARD_TOOLS: "
        f"missing_from_card={missing_from_card}, extra_in_card={extra_in_card}"
    )


def test_live_mcp_server_lists_same_tool_names_as_server_card() -> None:
    """Live FastMCP registration must expose the same tool names as the card."""
    pytest.importorskip("mcp", reason="mcp SDK not installed")
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    live_names = {tool.name for tool in asyncio.run(server.list_tools())}
    assert live_names == server_card_tool_names()
