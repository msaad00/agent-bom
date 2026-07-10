"""Canonical MCP catalog drift guard (#3675 PR-E).

Registered ``@mcp.tool`` names must match ``_SERVER_CARD_TOOLS`` exactly so
server-card metadata, Docker MCP registry exports, and live tool listing stay
aligned.
"""

from __future__ import annotations

import asyncio

import pytest

from agent_bom.mcp_server_metadata import (
    build_server_card,
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


def test_no_write_tool_is_labeled_read_only() -> None:
    """A tool whose capability class set includes WRITE must never advertise
    readOnlyHint=True — that mislabel tells a client the call is side-effect free
    when it actually mutates state (see access_review / diff)."""
    offenders = []
    for tool in build_server_card()["tools"]:
        classes = set(tool.get("capability_classes", []))
        annotations = tool.get("annotations", {}) or {}
        if "WRITE" in classes and annotations.get("readOnlyHint") is True:
            offenders.append(tool["name"])
    assert not offenders, f"WRITE tools mislabeled readOnlyHint=True: {offenders}"


def test_access_review_and_diff_are_labeled_write() -> None:
    """Regression: both persist state and must be WRITE, not read-only."""
    tools = {t["name"]: t for t in build_server_card()["tools"]}
    for name in ("access_review", "diff"):
        classes = set(tools[name].get("capability_classes", []))
        annotations = tools[name].get("annotations", {}) or {}
        assert "WRITE" in classes, f"{name} should be classified WRITE"
        assert annotations.get("readOnlyHint") is not True, f"{name} must not be readOnlyHint=True"
    # diff prunes/deletes older reports → destructive.
    assert tools["diff"]["annotations"].get("destructiveHint") is True


def test_previously_unclassified_operator_tools_have_capability_classes() -> None:
    """The nhi_discover / cloud_inventory / credential_expiry / cost_* / access_review
    tools were missing from _TOOL_CAPABILITY_CLASSES and silently defaulted to
    ['READ']; each must now carry an explicit, non-default class list."""
    tools = {t["name"]: t for t in build_server_card()["tools"]}
    for name in ("access_review", "nhi_discover", "cloud_inventory", "credential_expiry", "cost_forecast", "cost_allocation"):
        classes = tools[name].get("capability_classes", [])
        assert classes and classes != ["READ"], f"{name} still has the default capability class"


def test_live_access_review_and_diff_annotations_are_not_read_only() -> None:
    """The live FastMCP tool annotations for the two writers must not be read-only."""
    pytest.importorskip("mcp", reason="mcp SDK not installed")
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    for name in ("access_review", "diff"):
        annotations = getattr(tools[name], "annotations", None)
        assert annotations is not None, f"{name} should carry annotations"
        assert annotations.readOnlyHint is not True, f"{name} live annotation must not be readOnlyHint=True"
    assert tools["diff"].annotations.destructiveHint is True
