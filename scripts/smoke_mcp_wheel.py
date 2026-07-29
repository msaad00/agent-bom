#!/usr/bin/env python3
"""Exercise MCP initialize and tools/list from an installed release wheel.

Run this script with the Python interpreter from a clean environment containing
only an unlocked ``pip install dist/agent_bom-*.whl``.  It deliberately imports
the advertised server entry point before starting a real stdio MCP client
session, catching dependency-major drift that metadata-only wheel checks miss.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import sys
import traceback
from pathlib import Path

EXPECTED_TOOL_COUNT = 77


async def _smoke() -> dict[str, object]:
    importlib.import_module("agent_bom.mcp_server")

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    child_env = dict(os.environ)
    child_env["AGENT_BOM_SKIP_UPDATE_CHECK"] = "1"
    executable = Path(sys.executable).with_name("agent-bom")
    if not executable.is_file():
        raise RuntimeError(f"installed agent-bom console script is missing: {executable}")
    server = StdioServerParameters(
        command=str(executable),
        args=["mcp", "server"],
        env=child_env,
    )
    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            initialized = await session.initialize()
            listed = await session.list_tools()

    tool_names = [tool.name for tool in listed.tools]
    if len(tool_names) != EXPECTED_TOOL_COUNT:
        raise RuntimeError(f"MCP tools/list returned {len(tool_names)} tools; expected {EXPECTED_TOOL_COUNT}")
    if len(set(tool_names)) != len(tool_names):
        raise RuntimeError("MCP tools/list returned duplicate tool names")

    return {
        "protocol_version": initialized.protocolVersion,
        "server_name": initialized.serverInfo.name,
        "server_version": initialized.serverInfo.version,
        "tool_count": len(tool_names),
    }


def main() -> int:
    try:
        evidence = asyncio.run(asyncio.wait_for(_smoke(), timeout=90))
    except Exception as exc:
        print(f"MCP wheel smoke failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 1
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
