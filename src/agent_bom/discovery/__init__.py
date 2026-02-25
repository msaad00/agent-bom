"""Auto-discover MCP client configurations on the system."""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Optional

import yaml
from rich.console import Console

from agent_bom.models import Agent, AgentStatus, AgentType, MCPServer, TransportType
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
    AgentType.ROO_CODE: {
        # Roo Code VS Code extension (formerly Roo Cline)
        "Darwin": ["~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json"],
        "Linux": ["~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json"],
        "Windows": ["~/AppData/Roaming/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json"],
    },
    AgentType.AMAZON_Q: {
        # Amazon Q Developer VS Code extension
        "Darwin": ["~/Library/Application Support/Code/User/globalStorage/amazonwebservices.amazon-q-vscode/mcp.json"],
        "Linux": ["~/.config/Code/User/globalStorage/amazonwebservices.amazon-q-vscode/mcp.json"],
        "Windows": ["~/AppData/Roaming/Code/User/globalStorage/amazonwebservices.amazon-q-vscode/mcp.json"],
    },
    AgentType.TOOLHIVE: {
        # ToolHive MCP server manager — discovery via `thv list`, not config files
        "Darwin": [],
        "Linux": [],
        "Windows": [],
    },
    AgentType.DOCKER_MCP: {
        # Docker Desktop MCP Toolkit — discovery via registry.yaml + catalog
        "Darwin": [],
        "Linux": [],
        "Windows": [],
    },
}

# Map agent types to their CLI binary names for installed-but-not-configured detection
AGENT_BINARIES: dict[AgentType, str] = {
    AgentType.CLAUDE_CODE: "claude",
    AgentType.OPENCLAW: "openclaw",
    AgentType.TOOLHIVE: "thv",
    AgentType.ZED: "zed",
    AgentType.CURSOR: "cursor",
    AgentType.WINDSURF: "windsurf",
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


def get_all_discovery_paths(plat: Optional[str] = None) -> list[tuple[str, str]]:
    """Return all config paths that would be checked during discovery.

    Returns a list of (client_name, path_string) tuples for the given platform.
    Used by --dry-run and ``agent-bom paths`` for full transparency.
    """
    plat = plat or get_platform()
    paths: list[tuple[str, str]] = []
    for agent_type, platforms in CONFIG_LOCATIONS.items():
        for p in platforms.get(plat, []):
            paths.append((agent_type.value, p))
    # Docker MCP Toolkit paths (not in CONFIG_LOCATIONS)
    paths.append(("Docker MCP Toolkit", "~/.docker/mcp/registry.yaml"))
    paths.append(("Docker MCP Toolkit", "~/.docker/mcp/catalogs/docker-mcp.yaml"))
    # Project-level configs (relative to CWD)
    for pf in PROJECT_CONFIG_FILES:
        paths.append(("Project config", pf))
    # Docker Compose files (relative to CWD)
    for cf in COMPOSE_FILE_NAMES:
        paths.append(("Docker Compose", cf))
    return paths


def parse_mcp_config(config_data: dict, config_path: str) -> list[MCPServer]:
    """Parse MCP server definitions from a config file.

    Supports multiple config formats:
    - Standard (Claude Desktop, Cursor, Windsurf, Cortex Code):
        {"mcpServers": {"name": {"command": ..., "args": [...]}}}
    - VS Code native MCP (mcp.json):
        {"servers": {"name": {"type": "stdio", "command": ..., "args": [...]}}}
        {"servers": {"name": {"type": "http", "uri": "http://..."}}}
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
        # VS Code native format uses "type" field + "uri"; standard format uses "url"
        transport = TransportType.STDIO
        url = None
        vscode_type = server_def.get("type", "")
        if vscode_type == "sse":
            transport = TransportType.SSE
            url = server_def.get("uri") or server_def.get("url")
        elif vscode_type == "http":
            transport = TransportType.STREAMABLE_HTTP
            url = server_def.get("uri") or server_def.get("url")
        elif "url" in server_def or "uri" in server_def:
            url = server_def.get("url") or server_def.get("uri")
            if url and "sse" in url.lower():
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

        # Detect privilege indicators from command/args
        from agent_bom.models import PermissionProfile
        from agent_bom.permissions import command_is_shell, command_runs_as_root
        safe_args = server.args if isinstance(server.args, list) else [server.args]
        is_root = command_runs_as_root(command, safe_args)
        is_shell = command_is_shell(command, safe_args)
        if is_root or is_shell:
            server.permission_profile = PermissionProfile(
                runs_as_root=is_root,
                shell_access=is_shell,
            )

        # Try to determine working directory from args
        for arg in server.args:
            if os.path.isdir(arg):
                server.working_dir = arg
                break

        servers.append(server)

    return servers


def parse_claude_json_projects(config_data: dict, config_path: str) -> list[MCPServer]:
    """Parse Claude Code project-level MCP servers from ~/.claude.json.

    ``claude mcp add`` stores servers under projects.<path>.mcpServers.
    This iterates all project entries and collects their MCP servers.
    """
    servers: list[MCPServer] = []
    projects = config_data.get("projects", {})
    for project_path, project_data in projects.items():
        if not isinstance(project_data, dict):
            continue
        mcp_servers = project_data.get("mcpServers", {})
        if mcp_servers and isinstance(mcp_servers, dict):
            project_servers = parse_mcp_config(
                {"mcpServers": mcp_servers}, config_path
            )
            for s in project_servers:
                s.working_dir = project_path
            servers.extend(project_servers)
    return servers


def _parse_toolhive_servers(data) -> list[MCPServer]:
    """Parse ToolHive ``thv list --output json`` into MCPServer objects."""
    servers: list[MCPServer] = []
    items = data if isinstance(data, list) else data.get("servers", [])
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name", "")
        if not name:
            continue

        url = item.get("url") or item.get("endpoint")
        transport = TransportType.STDIO
        if url:
            transport = TransportType.SSE if "sse" in url.lower() else TransportType.STREAMABLE_HTTP

        server = MCPServer(
            name=name,
            command=item.get("image", "thv"),
            args=[],
            transport=transport,
            url=url,
            config_path="thv",
        )
        servers.append(server)
    return servers


def discover_toolhive() -> Optional[Agent]:
    """Discover MCP servers managed by ToolHive via ``thv list``.

    Returns an Agent with CONFIGURED status if servers are found,
    INSTALLED_NOT_CONFIGURED if thv is on PATH but no servers,
    or None if thv is not installed.
    """
    if not shutil.which("thv"):
        return None

    try:
        result = subprocess.run(
            ["thv", "list", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return Agent(
            name="toolhive",
            agent_type=AgentType.TOOLHIVE,
            config_path="thv (binary on PATH)",
            status=AgentStatus.INSTALLED_NOT_CONFIGURED,
        )

    if result.returncode != 0:
        return Agent(
            name="toolhive",
            agent_type=AgentType.TOOLHIVE,
            config_path="thv (binary on PATH)",
            status=AgentStatus.INSTALLED_NOT_CONFIGURED,
        )

    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return Agent(
            name="toolhive",
            agent_type=AgentType.TOOLHIVE,
            config_path="thv (binary on PATH)",
            status=AgentStatus.INSTALLED_NOT_CONFIGURED,
        )

    servers = _parse_toolhive_servers(data)
    if not servers:
        return Agent(
            name="toolhive",
            agent_type=AgentType.TOOLHIVE,
            config_path="thv (binary on PATH)",
            status=AgentStatus.INSTALLED_NOT_CONFIGURED,
        )

    return Agent(
        name="toolhive",
        agent_type=AgentType.TOOLHIVE,
        config_path="thv",
        mcp_servers=servers,
        status=AgentStatus.CONFIGURED,
    )


def detect_installed_agents(discovered_types: set[AgentType]) -> list[Agent]:
    """Detect agent CLIs on PATH that weren't found via config files.

    Returns agents with status=INSTALLED_NOT_CONFIGURED for visibility.
    """
    installed: list[Agent] = []
    for agent_type, binary_name in AGENT_BINARIES.items():
        if agent_type in discovered_types:
            continue
        if agent_type == AgentType.TOOLHIVE:
            continue  # Handled by discover_toolhive()
        if shutil.which(binary_name):
            installed.append(Agent(
                name=agent_type.value,
                agent_type=agent_type,
                config_path=f"{binary_name} (binary on PATH)",
                status=AgentStatus.INSTALLED_NOT_CONFIGURED,
            ))
    return installed


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

                    # Claude Code ~/.claude.json has project-level MCP servers
                    if agent_type == AgentType.CLAUDE_CODE and config_path.name == ".claude.json":
                        servers = servers + parse_claude_json_projects(config_data, str(config_path))

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


def _parse_docker_mcp_catalog(
    enabled_names: set[str],
    catalog_path: Path,
) -> list[MCPServer]:
    """Parse Docker MCP catalog YAML and return MCPServer objects for enabled servers.

    The catalog at ``~/.docker/mcp/catalogs/docker-mcp.yaml`` contains 300+
    server definitions with image refs, tool lists, secrets, and metadata.
    We only parse entries that the user has enabled in ``registry.yaml``.
    """
    from agent_bom.models import MCPTool, Package

    try:
        catalog_data = yaml.safe_load(catalog_path.read_text())
    except Exception:
        return []

    registry = catalog_data.get("registry", {})
    servers: list[MCPServer] = []

    for name in enabled_names:
        entry = registry.get(name)
        if not entry or not isinstance(entry, dict):
            continue

        image_ref = entry.get("image", "")

        # Build MCPTool objects from catalog tool list
        tools: list[MCPTool] = []
        for tool_entry in entry.get("tools", []):
            if isinstance(tool_entry, dict) and tool_entry.get("name"):
                tools.append(MCPTool(
                    name=tool_entry["name"],
                    description=tool_entry.get("description", ""),
                ))

        # Map secrets to credential env vars (values redacted)
        cred_env: dict[str, str] = {}
        for secret in entry.get("secrets", []):
            if isinstance(secret, dict) and secret.get("env"):
                cred_env[secret["env"]] = "***REDACTED***"

        # Build Package from Docker image reference
        pkg_version = "latest"
        if "@sha256:" in image_ref:
            pkg_version = image_ref.split("@sha256:")[1][:12]
        elif ":" in image_ref:
            pkg_version = image_ref.split(":")[-1]

        pkg_name = image_ref.split("@")[0] if "@" in image_ref else image_ref
        packages = [Package(
            name=pkg_name,
            version=pkg_version,
            ecosystem="docker",
            is_direct=True,
        )]

        server = MCPServer(
            name=name,
            command=f"docker run {image_ref}",
            args=[],
            env=cred_env,
            transport=TransportType.STDIO,
            tools=tools,
            packages=packages,
            config_path=str(catalog_path),
        )
        servers.append(server)

    return servers


def discover_docker_mcp() -> Optional[Agent]:
    """Discover Docker Desktop MCP Toolkit servers.

    Reads ``~/.docker/mcp/registry.yaml`` for enabled servers, then
    cross-references with ``~/.docker/mcp/catalogs/docker-mcp.yaml``
    for image refs, tools, secrets, and metadata.
    """
    mcp_dir = Path(os.path.expanduser("~/.docker/mcp"))
    registry_path = mcp_dir / "registry.yaml"

    if not registry_path.exists():
        return None

    try:
        registry_data = yaml.safe_load(registry_path.read_text())
    except Exception:
        return None

    if not registry_data or not isinstance(registry_data, dict):
        return None

    registry_section = registry_data.get("registry", {})
    if not isinstance(registry_section, dict):
        return None

    enabled_names = set(registry_section.keys())
    if not enabled_names:
        return Agent(
            name="docker-mcp",
            agent_type=AgentType.DOCKER_MCP,
            config_path=str(registry_path),
            status=AgentStatus.INSTALLED_NOT_CONFIGURED,
        )

    # Cross-reference with catalog for full metadata
    catalog_path = mcp_dir / "catalogs" / "docker-mcp.yaml"
    servers: list[MCPServer] = []

    if catalog_path.exists():
        servers = _parse_docker_mcp_catalog(enabled_names, catalog_path)

    # For enabled servers not found in catalog, create minimal entries
    found_names = {s.name for s in servers}
    for name in enabled_names - found_names:
        servers.append(MCPServer(
            name=name,
            command="docker",
            args=[],
            transport=TransportType.STDIO,
            config_path=str(registry_path),
        ))

    return Agent(
        name="docker-mcp",
        agent_type=AgentType.DOCKER_MCP,
        config_path=str(registry_path),
        mcp_servers=servers,
        status=AgentStatus.CONFIGURED if servers else AgentStatus.INSTALLED_NOT_CONFIGURED,
    )


# Docker Compose file names to search for MCP server services
COMPOSE_FILE_NAMES = [
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
]

# Image prefixes that indicate MCP servers in Docker Compose
MCP_IMAGE_PREFIXES = (
    "mcp/",
    "ghcr.io/modelcontextprotocol/",
    "modelcontextprotocol/",
)


def discover_compose_mcp_servers(project_dir: Optional[str] = None) -> Optional[Agent]:
    """Discover MCP servers defined in Docker Compose files.

    Scans ``docker-compose.yml`` / ``compose.yml`` for services whose images
    match known MCP server patterns (e.g. ``mcp/playwright``, ``mcp/fetch``).
    """
    from agent_bom.models import Package

    search_dir = Path(project_dir) if project_dir else Path.cwd()
    compose_path: Optional[Path] = None
    for name in COMPOSE_FILE_NAMES:
        candidate = search_dir / name
        if candidate.exists():
            compose_path = candidate
            break

    if not compose_path:
        return None

    try:
        compose_data = yaml.safe_load(compose_path.read_text())
    except Exception:
        return None

    if not compose_data or not isinstance(compose_data, dict):
        return None

    services = compose_data.get("services", {})
    if not isinstance(services, dict):
        return None

    mcp_servers: list[MCPServer] = []

    for svc_name, svc_def in services.items():
        if not isinstance(svc_def, dict):
            continue

        image = svc_def.get("image", "")
        if not image:
            continue

        # Check if this service uses a known MCP server image
        is_mcp = any(image.startswith(prefix) for prefix in MCP_IMAGE_PREFIXES)
        if not is_mcp:
            continue

        # Extract version from image tag
        pkg_version = "latest"
        pkg_name = image
        if "@sha256:" in image:
            pkg_name = image.split("@")[0]
            pkg_version = image.split("@sha256:")[1][:12]
        elif ":" in image and not image.startswith("ghcr.io:"):
            parts = image.rsplit(":", 1)
            pkg_name = parts[0]
            pkg_version = parts[1]

        # Extract env vars (list or dict format)
        raw_env = svc_def.get("environment", {})
        env: dict[str, str] = {}
        if isinstance(raw_env, list):
            for entry in raw_env:
                if isinstance(entry, str) and "=" in entry:
                    k, _, v = entry.partition("=")
                    env[k] = v
        elif isinstance(raw_env, dict):
            env = {k: str(v) for k, v in raw_env.items()}

        # Redact sensitive values
        env = sanitize_env_vars(env)

        packages = [Package(
            name=pkg_name,
            version=pkg_version,
            ecosystem="docker",
            is_direct=True,
        )]

        server = MCPServer(
            name=svc_name,
            command=f"docker compose up {svc_name}",
            args=[],
            env=env,
            transport=TransportType.STDIO,
            packages=packages,
            config_path=str(compose_path),
        )
        mcp_servers.append(server)

    if not mcp_servers:
        return None

    return Agent(
        name="docker-compose",
        agent_type=AgentType.CUSTOM,
        config_path=str(compose_path),
        mcp_servers=mcp_servers,
    )


def discover_all(project_dir: Optional[str] = None) -> list[Agent]:
    """Run full discovery: global configs + project configs + CLI agents."""
    console.print("\n[bold blue]🔍 Discovering MCP configurations...[/bold blue]\n")

    agents = discover_global_configs()

    if project_dir:
        agents.extend(discover_project_configs(project_dir))
    else:
        agents.extend(discover_project_configs())

    # Docker Compose MCP server discovery
    compose_agent = discover_compose_mcp_servers(project_dir)
    if compose_agent:
        console.print(
            f"  [green]✓[/green] Found {len(compose_agent.mcp_servers)} MCP "
            f"server(s) in Docker Compose: {compose_agent.config_path}"
        )
        agents.append(compose_agent)

    # ToolHive CLI-based discovery
    thv_agent = discover_toolhive()
    if thv_agent:
        if thv_agent.mcp_servers:
            console.print(
                f"  [green]✓[/green] Found toolhive with "
                f"{len(thv_agent.mcp_servers)} MCP server(s) (via thv list)"
            )
        else:
            console.print(
                "  [dim]  toolhive: installed but not configured[/dim]"
            )
        agents.append(thv_agent)

    # Docker Desktop MCP Toolkit discovery
    docker_agent = discover_docker_mcp()
    if docker_agent:
        if docker_agent.mcp_servers:
            total_tools = sum(len(s.tools) for s in docker_agent.mcp_servers)
            console.print(
                f"  [green]✓[/green] Found docker-mcp with "
                f"{len(docker_agent.mcp_servers)} enabled server(s), "
                f"{total_tools} tool(s) (via Docker Desktop MCP Toolkit)"
            )
        else:
            console.print(
                "  [dim]  docker-mcp: installed but not configured[/dim]"
            )
        agents.append(docker_agent)

    # Detect installed-but-not-configured agents
    discovered_types = {a.agent_type for a in agents}
    installed_agents = detect_installed_agents(discovered_types)
    for ia in installed_agents:
        console.print(
            f"  [dim]  {ia.name}: installed but not configured[/dim]"
        )
    agents.extend(installed_agents)

    configured = [a for a in agents if a.status == AgentStatus.CONFIGURED]
    if not configured and not installed_agents:
        console.print("  [yellow]No MCP configurations found.[/yellow]")
    else:
        total_servers = sum(len(a.mcp_servers) for a in configured)
        console.print(
            f"\n  [bold]Found {len(configured)} configured agent(s) with "
            f"{total_servers} MCP server(s) total.[/bold]"
        )
        if installed_agents:
            console.print(
                f"  [dim]{len(installed_agents)} additional agent(s) installed "
                f"but not configured.[/dim]"
            )

    return agents
