#!/usr/bin/env python3
"""Generate the Docker MCP argument inventory from the default live tool schemas."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "integrations/docker-mcp-registry/tools.json"


def render() -> str:
    from agent_bom.mcp_server import create_mcp_server

    tools = asyncio.run(create_mcp_server().list_tools())
    rows = []
    for tool in tools:
        arguments = []
        for name, schema in tool.inputSchema.get("properties", {}).items():
            types = [s.get("type") for s in schema.get("anyOf", []) if s.get("type") != "null"]
            arguments.append(
                {"name": name, "type": schema.get("type") or next((t for t in types if t), "object"), "desc": schema.get("description", "")}
            )
        rows.append({"name": tool.name, "description": tool.description or "", "arguments": arguments})
    return json.dumps(rows, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.check:
        if TARGET.read_text() != expected:
            print("Docker MCP argument inventory is stale; run scripts/generate_mcp_profile_catalog.py")
            return 1
    else:
        TARGET.write_text(expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
