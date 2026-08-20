#!/usr/bin/env python3
"""Boot an installed release wheel over stdio JSON-RPC and audit its live surface.

Run this with the Python interpreter from a clean environment containing only an
unlocked ``pip install dist/agent_bom-*.whl``. It starts the real
``agent-bom mcp server`` as a subprocess and speaks actual MCP to it, catching
dependency-major drift that metadata-only wheel checks miss.

Two things changed after a release shipped a stale surface claim:

*Expectations are derived, never typed.* This script used to assert
``len(tools) == 77``. A literal like that is correct the day it is written and
becomes the next stale claim the moment the surface moves — the same failure mode
that left the docs advertising 1013 registry entries against 1081 shipped. The
expectation now comes from the wheel's own server card
(``agent_bom.mcp_server_metadata``), so the check is "the running server matches
the card it publishes", which stays true across every future surface change.

*Resources and prompts are audited too.* Only ``tools/list`` was ever exercised
live. Nothing compared ``resources/list`` or ``prompts/list`` against anything,
and the HTTP server-card route serves those two straight from the static lists
without consulting the live registry — so a resource present in the card but
never registered (or registered but absent from the card) was invisible to every
test and every workflow.

Names are compared, not counts. Two counts can match while the sets differ.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import os
import sys
import traceback
from pathlib import Path

DEFAULT_TIMEOUT_SECONDS = 120


def _server_args() -> list[str]:
    """Launch the profile represented by the published server card."""
    return ["mcp", "server", "--profile", "full"]


def _expected_surface() -> dict[str, set[str]]:
    """Derive the advertised surface from the installed package's server card."""
    metadata = importlib.import_module("agent_bom.mcp_server_metadata")
    return {
        "tools": {str(tool["name"]) for tool in metadata._SERVER_CARD_TOOLS},
        "resources": {str(resource["uri"]) for resource in metadata._SERVER_CARD_RESOURCES},
        "prompts": {str(prompt["name"]) for prompt in metadata._SERVER_CARD_PROMPTS},
    }


def _compare(kind: str, live: list[str], expected: set[str]) -> list[str]:
    problems: list[str] = []
    duplicates = sorted({name for name in live if live.count(name) > 1})
    if duplicates:
        problems.append(f"{kind}: live server returned duplicate entries: {duplicates}")
    missing = sorted(expected - set(live))
    extra = sorted(set(live) - expected)
    if missing:
        problems.append(f"{kind}: advertised by the server card but not registered live: {missing}")
    if extra:
        problems.append(f"{kind}: registered live but missing from the server card: {extra}")
    return problems


async def _smoke() -> dict[str, object]:
    importlib.import_module("agent_bom.mcp_server")
    agent_bom = importlib.import_module("agent_bom")
    expected = _expected_surface()

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    child_env = dict(os.environ)
    child_env["AGENT_BOM_SKIP_UPDATE_CHECK"] = "1"
    # Third-party MCP tool plugins register extra tools at runtime, which would
    # legitimately exceed the server card. Audit the shipped surface only.
    child_env.pop("AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS", None)
    child_env.pop("AGENT_BOM_ACTIVATE_MCP_TOOL_PLUGINS", None)

    executable = Path(sys.executable).with_name("agent-bom")
    if not executable.is_file():
        raise RuntimeError(f"installed agent-bom console script is missing: {executable}")
    server = StdioServerParameters(command=str(executable), args=_server_args(), env=child_env)

    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            initialized = await session.initialize()
            tools = [tool.name for tool in (await session.list_tools()).tools]
            resources = [str(resource.uri) for resource in (await session.list_resources()).resources]
            prompts = [prompt.name for prompt in (await session.list_prompts()).prompts]

    problems = (
        _compare("tools", tools, expected["tools"])
        + _compare("resources", resources, expected["resources"])
        + _compare("prompts", prompts, expected["prompts"])
    )

    # The version a client sees on `initialize` is the release it is talking to.
    if initialized.serverInfo.version != agent_bom.__version__:
        problems.append(f"serverInfo.version {initialized.serverInfo.version!r} != package version {agent_bom.__version__!r}")
    if initialized.serverInfo.name != "agent-bom":
        problems.append(f"serverInfo.name {initialized.serverInfo.name!r} != 'agent-bom'")

    if problems:
        raise RuntimeError("live MCP surface disagrees with the shipped server card:\n  - " + "\n  - ".join(problems))

    return {
        "protocol_version": initialized.protocolVersion,
        "server_name": initialized.serverInfo.name,
        "server_version": initialized.serverInfo.version,
        "tool_count": len(tools),
        "resource_count": len(resources),
        "prompt_count": len(prompts),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    args = parser.parse_args(argv)
    try:
        evidence = asyncio.run(asyncio.wait_for(_smoke(), timeout=args.timeout))
    except Exception as exc:
        print(f"MCP wheel smoke failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 1
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
