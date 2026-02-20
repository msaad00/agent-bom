"""Auto-discover MCP client configurations on the system."""

from __future__ import annotations

import json
import logging
import os
import platform
from pathlib import Path
from typing import Optional

from rich.console import Console

from agent_bom.models import Agent, AgentType, MCPServer, TransportType
from agent_bom.security import (
    SecurityError,
    sanitize_env_vars,
    validate_json_file,
    validate_mcp_server_config,
    validate_path,
)

console = Console(stderr=True)
logger = logging.getLogger(__name__)

# Config file locations per platform
CONFIG_LOCATIONS: dict[AgentType, dict[str, list[str]]] = {
    AgentType.CLAUDE_DESKTOP: {
        "Darwin": ["~/Library/Application Support/Claude/claude_desktop_config.json"],
        "Linux": ["~/.config/Claude/claude_desktop_config.json"],
        "Windows": ["~/AppData/Roaming/Claude/claude_desktop_config.json"],
    },
    AgentType.CLAUDE_CODE: {
        "Darwin": ["~/.claude/settings.json", "~/.claude.json"],
        "Linux": ["~/.claude/settings.json", "~/.claude.json"],
        "Windows": ["~/.claude/settings.json", "~/.claude.json"],
    },
    AgentType.CURSOR: {
        "Darwin": ["~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json",
                    "~/.cursor/mcp.json"],
        "Linux": ["~/.config/Cursor/User/globalStorage/cursor.mcp/mcp.json",
                   "~/.cursor/mcp.json"],
        "Windows": ["~/AppData/Roaming/Cursor/User/globalStorage/cursor.mcp/mcp.json",
                     "~/.cursor/mcp.json"],
    },
    AgentType.WINDSURF: {
        "Darwin": ["~/.windsurf/mcp.json",
                    "~/Library/Application Support/Windsurf/User/globalStorage/windsurf.mcp/mcp.json"],
        "Linux": ["~/.windsurf/mcp.json"],
        "Windows": ["~/.windsurf/mcp.json"],
    },
    AgentType.CLINE: {
        "Darwin": ["~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"],
        "Linux": ["~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"],
        "Windows": ["~/AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"],
    },
    AgentType.VSCODE_COPILOT: {
        # VS Code Copilot Agent mode global MCP config (in addition to workspace .vscode/mcp.json)
        "Darwin": ["~/Library/Application Support/Code/User/mcp.json"],
        "Linux": ["~/.config/Code/User/mcp.json"],
        "Windows": ["~/AppData/Roaming/Code/User/mcp.json"],
    },
    AgentType.CORTEX_CODE: {
        # Snowflake Cortex Code CLI — cortex mcp add writes to this file
        "Darwin": ["~/.snowflake/cortex/mcp.json"],
        "Linux": ["~/.snowflake/cortex/mcp.json"],
        "Windows": ["~/.snowflake/cortex/mcp.json"],
    },
    AgentType.CONTINUE: {
        # Continue.dev VS Code extension
        "Darwin": ["~/.continue/config.json",
                   "~/Library/Application Support/Code/User/globalStorage/continue.continue/config.json"],
        "Linux": ["~/.continue/config.json",
                  "~/.config/Code/User/globalStorage/continue.continue/config.json"],
        "Windows": ["~/.continue/config.json",
                    "~/AppData/Roaming/Code/User/globalStorage/continue.continue/config.json"],
    },
    AgentType.ZED: {
        # Zed editor MCP config
        "Darwin": ["~/.config/zed/settings.json"],
        "Linux": ["~/.config/zed/settings.json"],
        "Windows": ["~/AppData/Roaming/Zed/settings.json"],
    },
    AgentType.OPENCLAW: {
        # OpenClaw AI agent — https://github.com/openclaw/openclaw
        # Config dir: ~/.openclaw/ on all platforms (resolveConfigDir in src/utils.ts)
        # Override via OPENCLAW_STATE_DIR env var
        "Darwin": ["~/.openclaw/openclaw.json"],
        "Linux": ["~/.openclaw/openclaw.json"],
        "Windows": ["~/.openclaw/openclaw.json"],
    },
}

# Project-level config files to search for
PROJECT_CONFIG_FILES = [
    ".mcp.json",
    "mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".openclaw/openclaw.json",
]


def get_platform() -> str:
    return platform.system()


def expand_path(path_str: str) -> Path:
    return Path(os.path.expanduser(path_str)).resolve()


def parse_mcp_config(config_data: dict, config_path: str) -> list[MCPServer]:
    """Parse MCP server definitions from a config file.

    Supports multiple config formats:
    - Standard (Claude Desktop, Cursor, Windsurf, Cortex Code):
        {"mcpServers": {"name": {"command": ..., "args": [...]}}}
    - OpenClaw (openclaw.json — agent config + optional mcpServers):
        {"agent": {...}, "mcpServers": {"name": {"command": ..., "args": [...]}}}
    - Continue.dev (array format):
        {"mcpServers": [{"name": "...", "command": ..., "args": [...]}]}
    - Zed editor:
        {"context_servers": {"name": {"command": {"path": ..., "args": [...]}}}}
    """
    servers = []
    raw = config_data.get("mcpServers", config_data.get("servers", {}))

    # Normalize: Continue.dev uses an array instead of an object
    if isinstance(raw, list):
        mcp_servers = {item["name"]: item for item in raw if isinstance(item, dict) and "name" in item}
    else:
        mcp_servers = raw

    # Zed uses "context_servers" with a nested "command" object
    if not mcp_servers and "context_servers" in config_data:
        for name, ctx in config_data["context_servers"].items():
            if isinstance(ctx, dict) and "command" in ctx:
                cmd_obj = ctx["command"]
                if isinstance(cmd_obj, dict):
                    mcp_servers[name] = {
                        "command": cmd_obj.get("path", ""),
                        "args": cmd_obj.get("args", []),
                        "env": ctx.get("env", {}),
                    }

    for name, server_def in mcp_servers.items():
        if not isinstance(server_def, dict):
            continue

        # ✅ Security: Validate MCP server configuration
        try:
            validate_mcp_server_config(server_def)
        except SecurityError as e:
            logger.warning(f"Skipping insecure MCP server '{name}': {e}")
            console.print(f"[yellow]⚠️  Skipped insecure server '{name}': {e}[/yellow]")
            continue

        # Determine transport type
        transport = TransportType.STDIO
        url = None
        if "url" in server_def:
            url = server_def["url"]
            if "sse" in url.lower():
                transport = TransportType.SSE
            else:
                transport = TransportType.STREAMABLE_HTTP

        command = server_def.get("command", "")
        args = server_def.get("args", [])
        raw_env = server_def.get("env", {})

        # ✅ Security: redact credential values before storing in MCPServer
        # Only env var NAMES appear in reports — values are replaced with ***REDACTED***
        env = sanitize_env_vars(raw_env) if isinstance(raw_env, dict) else {}

        server = MCPServer(
            name=name,
            command=command,
            args=args if isinstance(args, list) else [args],
            env=env,
            transport=transport,
            url=url,
            config_path=config_path,
        )

        # Try to determine working directory from args
        for arg in server.args:
            if os.path.isdir(arg):
                server.working_dir = arg
                break

        servers.append(server)

    return servers


def discover_global_configs(agent_types: Optional[list[AgentType]] = None) -> list[Agent]:
    """Discover all global MCP client configurations."""
    agents = []
    sys_platform = get_platform()

    if agent_types is None:
        agent_types = list(CONFIG_LOCATIONS.keys())

    for agent_type in agent_types:
        locations = CONFIG_LOCATIONS.get(agent_type, {})
        platform_paths = locations.get(sys_platform, [])

        for path_str in platform_paths:
            config_path = expand_path(path_str)
            if config_path.exists():
                try:
                    config_data = json.loads(config_path.read_text())
                    servers = parse_mcp_config(config_data, str(config_path))

                    if servers:
                        agent = Agent(
                            name=agent_type.value,
                            agent_type=agent_type,
                            config_path=str(config_path),
                            mcp_servers=servers,
                        )
                        agents.append(agent)
                        console.print(
                            f"  [green]✓[/green] Found {agent_type.value} with "
                            f"{len(servers)} MCP server(s): {config_path}"
                        )
                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    console.print(
                        f"  [yellow]⚠[/yellow] Error parsing {config_path}: {e}"
                    )

    return agents


def discover_project_configs(project_dir: Optional[str] = None) -> list[Agent]:
    """Discover project-level MCP configurations."""
    agents = []
    search_dir = Path(project_dir) if project_dir else Path.cwd()

    for config_name in PROJECT_CONFIG_FILES:
        config_path = search_dir / config_name
        if config_path.exists():
            try:
                config_data = json.loads(config_path.read_text())
                servers = parse_mcp_config(config_data, str(config_path))

                if servers:
                    agent = Agent(
                        name=f"project:{search_dir.name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=str(config_path),
                        mcp_servers=servers,
                    )
                    agents.append(agent)
                    console.print(
                        f"  [green]✓[/green] Found project config with "
                        f"{len(servers)} MCP server(s): {config_path}"
                    )
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                console.print(
                    f"  [yellow]⚠[/yellow] Error parsing {config_path}: {e}"
                )

    return agents


def discover_all(project_dir: Optional[str] = None) -> list[Agent]:
    """Run full discovery: global configs + project configs."""
    console.print("\n[bold blue]🔍 Discovering MCP configurations...[/bold blue]\n")

    agents = discover_global_configs()

    if project_dir:
        agents.extend(discover_project_configs(project_dir))
    else:
        agents.extend(discover_project_configs())

    if not agents:
        console.print("  [yellow]No MCP configurations found.[/yellow]")
    else:
        total_servers = sum(len(a.mcp_servers) for a in agents)
        console.print(
            f"\n  [bold]Found {len(agents)} agent(s) with {total_servers} MCP server(s) total.[/bold]"
        )

    return agents
