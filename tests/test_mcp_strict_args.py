"""MCP strict-args contract (#2197 audit P1).

Pre-fix, every tool let unknown arg keys silently drop. AI agents passing
typo args (e.g. `Version` capital) got false-clean verdicts. The fix:

1. `additionalProperties: false` on every tool's JSON schema served via
   `tools/list`, so MCP clients can validate locally.
2. Runtime guard at the manager call boundary that rejects calls
   carrying unknown arg keys before FastMCP's Pydantic validation
   silently drops them.
"""

from __future__ import annotations

import asyncio

import pytest

from agent_bom.mcp_server import create_mcp_server


@pytest.fixture(scope="module")
def mcp_server():
    return create_mcp_server()


def test_every_tool_advertises_additional_properties_false(mcp_server) -> None:  # noqa: ANN001
    """Every registered tool's JSON schema must reject unknown properties."""
    tools = list(mcp_server._tool_manager._tools.values())
    assert len(tools) >= 30, f"expected ~36 tools, got {len(tools)}"
    leaks: list[str] = []
    for tool in tools:
        params = tool.parameters or {}
        if params.get("additionalProperties") is not False:
            leaks.append(tool.name)
    assert not leaks, f"tools missing additionalProperties:false: {leaks}"


def test_unknown_argument_raises_clear_error(mcp_server) -> None:  # noqa: ANN001
    """Calling a tool with a typo arg name fails loudly instead of silently
    dropping the arg (the audit's flask@2.0.0 false-clean repro)."""
    from mcp.server.fastmcp.exceptions import ToolError

    async def call() -> None:
        await mcp_server._tool_manager.call_tool(
            "check",
            {"package": "flask", "version": "2.0.0", "ecosystem": "pypi"},
        )

    with pytest.raises(ToolError) as exc:
        asyncio.run(call())
    msg = str(exc.value)
    assert "Unknown argument" in msg
    assert "version" in msg
    assert "check" in msg


def test_known_arguments_pass_through(mcp_server) -> None:  # noqa: ANN001
    """Sanity check: legitimate calls aren't blocked by the guard.

    Don't actually run the tool (it would do real network work); just
    confirm that the strict-args layer doesn't trip on the canonical
    arg shape. We use `inventory` because it accepts an optional
    `config_path` and runs locally.
    """

    async def call() -> object:
        return await mcp_server._tool_manager.call_tool(
            "inventory",
            {"config_path": None},
        )

    # The call may succeed or fail downstream (e.g. no MCP configs found),
    # but it should NOT raise a ToolError about unknown args.
    from mcp.server.fastmcp.exceptions import ToolError

    try:
        asyncio.run(call())
    except ToolError as e:
        assert "Unknown argument" not in str(e)


def test_harden_is_idempotent(mcp_server) -> None:  # noqa: ANN001
    """Calling harden_tool_arguments twice doesn't double-wrap."""
    from agent_bom.mcp_strict_args import harden_tool_arguments

    # First call already happened in create_mcp_server; this is the second.
    harden_tool_arguments(mcp_server)
    # Verify the manager's call_tool is still our wrapper (not a wrapper of
    # a wrapper -- the marker attribute prevents stacking).
    assert getattr(mcp_server._tool_manager.call_tool, "_agent_bom_strict", False) is True
