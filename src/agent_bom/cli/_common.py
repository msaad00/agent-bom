"""Shared helpers and constants for the CLI package."""

from __future__ import annotations

import importlib
import logging
import threading
from pathlib import Path

from rich.console import Console

from agent_bom import __version__
from agent_bom.security import sanitize_env_vars

logger = logging.getLogger(__name__)

BANNER = r"""
   ___                    __     ____  ____  __  ___
  / _ | ___ ____ ___  ___/ /_   / __ )/ __ \/  |/  /
 / __ |/ _ `/ -_) _ \/ __/_  / / __  / / / / /|_/ /
/_/ |_/\_, /\__/_//_/\__/ /_/ /____/\____/_/  /_/
      /___/
  Security scanner for AI infrastructure
"""

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, "unknown": -1}


def _make_console(quiet: bool = False, output_format: str = "console", no_color: bool = False) -> Console:
    """Create a Console that routes output correctly.

    - quiet mode: suppress all output
    - json/cyclonedx format: route to stderr (keep stdout clean for piping)
    - no_color: disable all ANSI styling (for piping / CI)
    - console format: normal stdout
    """
    if quiet:
        return Console(stderr=True, quiet=True)
    if output_format != "console":
        return Console(stderr=True, no_color=no_color)
    return Console(no_color=no_color)


def _sync_runtime_consoles(console: Console) -> None:
    """Point shared module-level consoles at the active CLI console."""
    for module_name in (
        "agent_bom.scanners",
        "agent_bom.enrichment",
        "agent_bom.resolver",
        "agent_bom.transitive",
        "agent_bom.parsers",
    ):
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not sync console for %s: %s", module_name, exc)
            continue
        if hasattr(module, "console"):
            setattr(module, "console", console)


def _build_agents_from_inventory(inventory_data: dict, source_path: str) -> list:
    """Build Agent objects from parsed inventory dict (JSON or CSV)."""
    from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

    agents = []
    for agent_data in inventory_data.get("agents", []):
        mcp_servers = []
        for server_data in agent_data.get("mcp_servers", []):
            # Parse pre-populated tools (e.g. from Snowflake/cloud inventory)
            tools = []
            for tool_data in server_data.get("tools", []):
                if isinstance(tool_data, str):
                    tools.append(MCPTool(name=tool_data, description=""))
                elif isinstance(tool_data, dict):
                    tools.append(
                        MCPTool(
                            name=tool_data.get("name", ""),
                            description=tool_data.get("description", ""),
                            input_schema=tool_data.get("input_schema"),
                        )
                    )

            # Parse pre-known packages (e.g. from cloud asset scan)
            packages = []
            for pkg_data in server_data.get("packages", []):
                if isinstance(pkg_data, str):
                    if "@" in pkg_data:
                        name, version = pkg_data.rsplit("@", 1)
                    else:
                        name, version = pkg_data, "unknown"
                    packages.append(Package(name=name, version=version, ecosystem="unknown"))
                elif isinstance(pkg_data, dict):
                    packages.append(
                        Package(
                            name=pkg_data.get("name", ""),
                            version=pkg_data.get("version", "unknown"),
                            ecosystem=pkg_data.get("ecosystem", "unknown"),
                            purl=pkg_data.get("purl"),
                        )
                    )

            server = MCPServer(
                name=server_data.get("name", ""),
                command=server_data.get("command", ""),
                args=server_data.get("args", []),
                env=sanitize_env_vars(server_data.get("env", {})),
                transport=TransportType(server_data.get("transport", "stdio")),
                url=server_data.get("url"),
                config_path=agent_data.get("config_path"),
                working_dir=server_data.get("working_dir"),
                mcp_version=server_data.get("mcp_version"),
                security_blocked=bool(server_data.get("security_blocked", False)),
                security_warnings=list(server_data.get("security_warnings", []) or []),
                security_intelligence=list(server_data.get("security_intelligence", []) or []),
                tools=tools,
                packages=packages,
            )
            mcp_servers.append(server)

        agent = Agent(
            name=agent_data.get("name", "unknown"),
            agent_type=AgentType(agent_data.get("agent_type", agent_data.get("type", "custom"))),
            config_path=agent_data.get("config_path", source_path),
            mcp_servers=mcp_servers,
            version=agent_data.get("version"),
            source=agent_data.get("source", inventory_data.get("source")),
        )
        agents.append(agent)

    return agents


_update_check_result: str | None = None
_update_check_done = threading.Event()


def _check_for_update_bg() -> None:
    """Background thread: compare __version__ against PyPI latest. Non-blocking."""
    global _update_check_result  # noqa: PLW0603
    try:
        cache_dir = Path.home() / ".cache" / "agent-bom"
        cache_file = cache_dir / "update-check.txt"
        cache_dir.mkdir(parents=True, exist_ok=True)

        # Only hit PyPI once per 24 hours
        import time

        if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < 86400:
            _update_check_result = cache_file.read_text().strip() or None
            _update_check_done.set()
            return

        from agent_bom.http_client import fetch_json

        data = fetch_json("https://pypi.org/pypi/agent-bom/json", timeout=5)
        latest = data["info"]["version"]

        def _vt(v: str) -> tuple[int, ...]:
            return tuple(int(x) for x in v.split(".") if x.isdigit())

        if _vt(latest) > _vt(__version__):
            msg = (
                f"[yellow]Update available:[/yellow] agent-bom {__version__} → [bold]{latest}[/bold]\n"
                f"  Run: [cyan]pip install --upgrade agent-bom[/cyan]"
            )
        else:
            msg = ""
        cache_file.write_text(msg)
        _update_check_result = msg or None
    except Exception:  # noqa: BLE001
        _update_check_result = None
    finally:
        _update_check_done.set()


def _print_update_notice(console: Console) -> None:
    """Print update notice if a newer version was found (non-blocking)."""
    _update_check_done.wait(timeout=0.1)  # don't block the user
    if _update_check_result:
        console.print()
        console.print(_update_check_result)


def _check_optional_dep(name: str) -> str:
    """Return 'found (vX.Y.Z)' or 'not installed' for an optional binary dep."""
    import shutil
    import subprocess

    path = shutil.which(name)
    if not path:
        return "not installed"
    try:
        result = subprocess.run([path, "version"], capture_output=True, text=True, timeout=3)  # noqa: S603
        ver = (result.stdout or result.stderr).strip().split("\n")[0]
        return f"found ({ver})" if ver else "found"
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not get version for %s: %s", name, exc)
        return "found"
