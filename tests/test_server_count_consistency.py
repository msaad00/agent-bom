"""Every console/report surface counts MCP servers the same way.

A project, SBOM or image scan wraps its packages in a non-MCP surface. The
summary already excluded those wrappers ("0 servers") while the Agents table,
dependency tree and HTML agent cards counted them ("Servers 1"), so a plain
repo scan contradicted itself. ``Agent.total_mcp_servers`` is the one source.
"""

from __future__ import annotations

import re
from io import StringIO

from rich.console import Console

import agent_bom.output as out_mod
from agent_bom.models import Agent, AgentStatus, AgentType, AIBOMReport, MCPServer, Package, ServerSurface, TransportType
from agent_bom.output import print_compact_agents, print_compact_summary
from agent_bom.output.html.sections import _inventory_cards


def _capture(fn, *args) -> str:
    buf = StringIO()
    original = out_mod.console
    out_mod.console = Console(file=buf, width=140, force_terminal=True, no_color=True)
    try:
        fn(*args)
    finally:
        out_mod.console = original
    return re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())


def _project_surface() -> MCPServer:
    return MCPServer(
        name="plainrepo",
        command="",
        transport=TransportType.STDIO,
        surface=ServerSurface.FILESYSTEM,
        packages=[Package(name="requests", version="2.31.0", ecosystem="pypi")],
    )


def _mcp_server() -> MCPServer:
    return MCPServer(name="filesystem", command="npx", args=["@mcp/server-filesystem"], transport=TransportType.STDIO)


def _report(*servers: MCPServer) -> AIBOMReport:
    agent = Agent(
        name="plainrepo",
        agent_type=AgentType.CUSTOM,
        config_path="/repo",
        mcp_servers=list(servers),
        status=AgentStatus.CONFIGURED,
    )
    return AIBOMReport(agents=[agent])


def _agents_table_servers(output: str) -> int:
    row = next(line for line in output.splitlines() if line.strip().startswith("plainrepo"))
    return int(row.split()[2])


def test_plain_repo_scan_reports_zero_servers_everywhere() -> None:
    report = _report(_project_surface())

    assert report.agents[0].total_mcp_servers == 0
    assert report.total_servers == 0
    assert "0 servers" in _capture(print_compact_summary, report)
    assert _agents_table_servers(_capture(print_compact_agents, report)) == 0
    assert "0 server(s)" in _inventory_cards(report)


def test_mcp_servers_are_counted_once_alongside_package_surfaces() -> None:
    report = _report(_project_surface(), _mcp_server())

    assert report.agents[0].total_mcp_servers == 1
    assert report.total_servers == 1
    assert "1 servers" in _capture(print_compact_summary, report)
    assert _agents_table_servers(_capture(print_compact_agents, report)) == 1
    assert "1 server(s)" in _inventory_cards(report)
