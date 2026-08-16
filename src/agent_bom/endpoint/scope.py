"""Truthful per-scope evidence for the workstation scan preset."""

from __future__ import annotations

import importlib.util
import platform
import shutil
import subprocess
from typing import Any

from agent_bom.evidence.scan_run import ScanScope, ScanScopeStatus


def _source_item_count(agents: list[Any], source: str) -> int:
    return sum(len(getattr(agent, "mcp_servers", []) or []) for agent in agents if getattr(agent, "source", "") == source)


def _package_count(agents: list[Any], sources: set[str]) -> int:
    return sum(
        len(getattr(server, "packages", []) or [])
        for agent in agents
        if getattr(agent, "source", "") in sources
        for server in (getattr(agent, "mcp_servers", []) or [])
    )


def _container_scope(agents: list[Any]) -> ScanScope:
    count = _source_item_count(agents, "container")
    if not shutil.which("docker"):
        return ScanScope(
            name="mcp_containers",
            status=ScanScopeStatus.UNAVAILABLE,
            message="Docker CLI is not available; MCP container evidence was not collected.",
        )
    try:
        probe = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ScanScope(
            name="mcp_containers",
            status=ScanScopeStatus.UNAVAILABLE,
            message="Docker runtime could not be reached; MCP container evidence was not collected.",
        )
    if probe.returncode != 0:
        return ScanScope(
            name="mcp_containers",
            status=ScanScopeStatus.UNAVAILABLE,
            message="Docker runtime could not be reached; MCP container evidence was not collected.",
        )
    return ScanScope(
        name="mcp_containers",
        status=ScanScopeStatus.COMPLETE,
        item_count=count,
        message="MCP-indicating running containers only.",
    )


def workstation_scan_scopes(
    *,
    agents: list[Any],
    browser_extension_count: int,
    context_graph_node_count: int,
    system: str | None = None,
) -> list[ScanScope]:
    """Describe every scope requested by ``--preset workstation``.

    ``complete`` means the collector ran successfully; a zero item count is a
    valid complete result. Unsupported or unavailable collectors are explicit
    and downgrade the enclosing scan rather than looking clean.
    """

    host_system = system or platform.system()
    process_count = _source_item_count(agents, "process")
    package_count = _package_count(agents, {"os-packages"})

    if host_system == "Linux":
        package_scope = ScanScope(name="os_packages", status=ScanScopeStatus.COMPLETE, item_count=package_count)
    elif host_system == "Darwin":
        package_scope = ScanScope(
            name="os_packages",
            status=ScanScopeStatus.UNSUPPORTED,
            message="Host package inventory is not implemented for macOS; Homebrew and installed apps were not evaluated.",
        )
    elif host_system == "Windows":
        package_scope = ScanScope(
            name="os_packages",
            status=ScanScopeStatus.UNSUPPORTED,
            message="Host package inventory is not implemented for Windows; installed applications were not evaluated.",
        )
    else:
        package_scope = ScanScope(
            name="os_packages",
            status=ScanScopeStatus.UNSUPPORTED,
            message=f"Host package inventory is not implemented for {host_system or 'this platform'}.",
        )

    if importlib.util.find_spec("psutil") is None:
        process_scope = ScanScope(
            name="mcp_processes",
            status=ScanScopeStatus.UNAVAILABLE,
            message="MCP process discovery requires the optional psutil dependency.",
        )
    else:
        process_scope = ScanScope(
            name="mcp_processes",
            status=ScanScopeStatus.COMPLETE,
            item_count=process_count,
            message="MCP server processes only; general process and service inventory is not evaluated.",
        )

    return [
        ScanScope(
            name="repository_inventory",
            status=ScanScopeStatus.COMPLETE,
            item_count=_package_count(agents, {"project", "filesystem"}),
            message="Repository dependencies and supported static evidence only; installed applications are a separate scope.",
        ),
        ScanScope(
            name="agents_mcp",
            status=ScanScopeStatus.COMPLETE,
            item_count=sum(len(getattr(agent, "mcp_servers", []) or []) for agent in agents),
        ),
        ScanScope(
            name="browser_extensions",
            status=ScanScopeStatus.COMPLETE,
            item_count=browser_extension_count,
            message="Medium-or-higher risk browser extensions reported by supported browser profiles.",
        ),
        package_scope,
        process_scope,
        _container_scope(agents),
        ScanScope(name="context_graph", status=ScanScopeStatus.COMPLETE, item_count=context_graph_node_count),
    ]
