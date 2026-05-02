"""Shared helpers and constants for the CLI package."""

from __future__ import annotations

import importlib
import json
import logging
import threading
from pathlib import Path
from typing import Any

import click
from rich.console import Console

from agent_bom import __version__
from agent_bom.mcp_blocklist import sanitize_security_intelligence_entry
from agent_bom.security import sanitize_env_vars, sanitize_sensitive_payload

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
PORT_RANGE = click.IntRange(1, 65535)
LISTEN_PORT_RANGE = click.IntRange(1024, 65535)
OPTIONAL_PORT_RANGE = click.IntRange(0, 65535)


def read_json_file_for_cli(path: str | Path, *, label: str = "JSON file") -> Any:
    """Read a JSON file and raise concise Click errors for CLI users."""
    file_path = Path(path)
    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"{label} JSON error in {file_path}: line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    except OSError as exc:
        raise click.ClickException(f"Could not read {label.lower()} {file_path}: {exc.strerror or exc}") from exc


import contextlib  # noqa: E402 — kept beside the helper that uses it for grep-locality


@contextlib.contextmanager
def rich_log_handler_during_progress(console: Console, *, logger_name: str = "agent_bom.scanners"):
    """Route warnings from ``logger_name`` through Rich for the duration.

    When a Rich ``Progress`` / ``Live`` region is active, a ``logger.warning(...)``
    that goes through a plain stderr handler punches through the live region:
    each warning line pushes the spinner down, the spinner redraws below it,
    and the terminal accumulates a stack of "Scanning N packages" lines
    instead of a single redrawing one.

    Bind a ``RichHandler`` to the same ``Console`` for the duration of the
    progress block so log records render *above* the live region without
    breaking the redraw, then restore the original handlers on exit.
    """
    from rich.logging import RichHandler

    target = logging.getLogger(logger_name)
    saved_handlers = list(target.handlers)
    saved_propagate = target.propagate

    rich_h = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=False,
        rich_tracebacks=False,
        log_time_format="%H:%M:%S",
        omit_repeated_times=False,
    )
    rich_h.setLevel(logging.WARNING)
    target.handlers = [rich_h]
    target.propagate = False
    try:
        yield
    finally:
        target.handlers = saved_handlers
        target.propagate = saved_propagate


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
    from agent_bom.asset_provenance import sanitize_discovery_provenance
    from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

    agents = []
    inventory_provenance = sanitize_discovery_provenance(
        inventory_data.get("discovery_provenance"),
        defaults={
            "source_type": "operator_pushed_inventory",
            "observed_via": ["operator_inventory"],
            "source": inventory_data.get("source"),
            "collector": "inventory",
            "confidence": "high",
        },
    )
    for agent_data in inventory_data.get("agents", []):
        mcp_servers = []
        agent_provenance = sanitize_discovery_provenance(
            agent_data.get("discovery_provenance"),
            defaults={
                **(inventory_provenance or {}),
                "source": agent_data.get("source", inventory_data.get("source")),
            },
        )
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
            package_provenance = sanitize_discovery_provenance(
                server_data.get("discovery_provenance"),
                defaults=agent_provenance,
            )
            for pkg_data in server_data.get("packages", []):
                if isinstance(pkg_data, str):
                    if "@" in pkg_data:
                        name, version = pkg_data.rsplit("@", 1)
                    else:
                        name, version = pkg_data, "unknown"
                    packages.append(
                        Package(
                            name=name,
                            version=version,
                            ecosystem="unknown",
                            discovery_provenance=package_provenance,
                        )
                    )
                elif isinstance(pkg_data, dict):
                    packages.append(
                        Package(
                            name=pkg_data.get("name", ""),
                            version=pkg_data.get("version", "unknown"),
                            ecosystem=pkg_data.get("ecosystem", "unknown"),
                            purl=pkg_data.get("purl"),
                            discovery_provenance=sanitize_discovery_provenance(
                                pkg_data.get("discovery_provenance"),
                                defaults=package_provenance,
                            ),
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
                security_intelligence=[
                    sanitize_security_intelligence_entry(item)
                    for item in (server_data.get("security_intelligence", []) or [])
                    if isinstance(item, dict)
                ],
                discovery_provenance=package_provenance,
                tools=tools,
                packages=packages,
            )
            mcp_servers.append(server)

        sanitized_metadata = {}
        if isinstance(agent_data.get("metadata"), dict):
            metadata_payload = sanitize_sensitive_payload(agent_data.get("metadata", {}))
            sanitized_metadata = metadata_payload if isinstance(metadata_payload, dict) else {}

        agent = Agent(
            name=agent_data.get("name", "unknown"),
            agent_type=AgentType(agent_data.get("agent_type", agent_data.get("type", "custom"))),
            config_path=agent_data.get("config_path", source_path),
            mcp_servers=mcp_servers,
            version=agent_data.get("version"),
            source=agent_data.get("source", inventory_data.get("source")),
            metadata=sanitized_metadata,
            discovered_at=agent_data.get("discovered_at") or agent_data.get("first_seen") or "",
            last_seen=agent_data.get("last_seen") or agent_data.get("last_seen_at"),
            discovery_provenance=agent_provenance,
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
