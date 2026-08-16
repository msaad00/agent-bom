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
    endpoint_inventory: dict[str, Any] | None = None,
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
            message="Native advisory package matching is not implemented for macOS; installed applications are reported separately.",
        )
    elif host_system == "Windows":
        package_scope = ScanScope(
            name="os_packages",
            status=ScanScopeStatus.UNSUPPORTED,
            message="Native Windows advisory package matching is not implemented; installed applications are reported separately.",
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

    scopes = [
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

    collector_rows = (endpoint_inventory or {}).get("collectors", [])
    collectors = {str(row.get("name")): row for row in collector_rows if isinstance(row, dict) and row.get("name")}

    def collector_scope(scope_name: str, collector_name: str) -> ScanScope:
        row = collectors.get(collector_name)
        if row is None:
            return ScanScope(
                name=scope_name,
                status=ScanScopeStatus.UNAVAILABLE,
                message=f"{collector_name} inventory did not return execution metadata.",
            )
        try:
            status = ScanScopeStatus(str(row.get("status") or "unavailable"))
        except ValueError:
            status = ScanScopeStatus.UNAVAILABLE
        count = row.get("item_count")
        return ScanScope(
            name=scope_name,
            status=status,
            item_count=int(count) if isinstance(count, int) else None,
            message=str(row.get("message") or ""),
        )

    if endpoint_inventory is not None:
        scopes.extend(
            [
                collector_scope("installed_applications", "applications"),
                collector_scope("running_processes", "processes"),
                collector_scope("services", "services"),
                collector_scope("listeners", "listeners"),
            ]
        )
        containers = collector_scope("container_assets", "containers")
        images = collector_scope("container_assets", "images")
        combined_status = containers.status
        if containers.status is not images.status:
            if ScanScopeStatus.COMPLETE in {containers.status, images.status}:
                combined_status = ScanScopeStatus.PARTIAL
            elif ScanScopeStatus.PERMISSION_DENIED in {containers.status, images.status}:
                combined_status = ScanScopeStatus.PERMISSION_DENIED
            else:
                combined_status = ScanScopeStatus.UNAVAILABLE
        combined_count = None
        if containers.item_count is not None and images.item_count is not None:
            combined_count = containers.item_count + images.item_count
        scopes.append(
            ScanScope(
                name="container_assets",
                status=combined_status,
                item_count=combined_count,
                message=" ".join(dict.fromkeys(filter(None, (containers.message, images.message)))),
            )
        )

    return scopes
