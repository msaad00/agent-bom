"""Auto-discover MCP client configurations on the system."""

from __future__ import annotations

import glob as glob_mod
import json
import logging
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Optional

import yaml  # type: ignore[import-untyped]
from rich.console import Console

# Re-export parser functions for backward compatibility
from agent_bom.discovery.config_parsers import (  # noqa: F401
    _DANGEROUS_HOOK_PATTERNS,
    _parse_docker_mcp_catalog,
    _parse_toolhive_servers,
    audit_cortex_hooks,
    audit_cortex_permissions,
    parse_claude_json_projects,
    parse_codex_config,
    parse_cortex_code_metadata,
    parse_goose_config,
    parse_mcp_config,
    parse_snowflake_connections,
)
from agent_bom.models import Agent, AgentStatus, AgentType, MCPServer, TransportType
from agent_bom.security import sanitize_env_vars

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
        "Darwin": ["~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json", "~/.cursor/mcp.json"],
        "Linux": ["~/.config/Cursor/User/globalStorage/cursor.mcp/mcp.json", "~/.cursor/mcp.json"],
        "Windows": ["~/AppData/Roaming/Cursor/User/globalStorage/cursor.mcp/mcp.json", "~/.cursor/mcp.json"],
    },
    AgentType.WINDSURF: {
        "Darwin": ["~/.windsurf/mcp.json", "~/Library/Application Support/Windsurf/User/globalStorage/windsurf.mcp/mcp.json"],
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
        # Snowflake Cortex Code CLI (CoCo) — MCP servers, permissions, hooks, settings
        "Darwin": [
            "~/.snowflake/cortex/mcp.json",
            "~/.snowflake/cortex/settings.json",
            "~/.snowflake/cortex/permissions.json",
            "~/.snowflake/cortex/hooks.json",
        ],
        "Linux": [
            "~/.snowflake/cortex/mcp.json",
            "~/.snowflake/cortex/settings.json",
            "~/.snowflake/cortex/permissions.json",
            "~/.snowflake/cortex/hooks.json",
        ],
        "Windows": [
            "~/.snowflake/cortex/mcp.json",
            "~/.snowflake/cortex/settings.json",
            "~/.snowflake/cortex/permissions.json",
            "~/.snowflake/cortex/hooks.json",
        ],
    },
    AgentType.CODEX_CLI: {
        # OpenAI Codex CLI — TOML config with [mcp_servers.*] tables
        "Darwin": ["~/.codex/config.toml"],
        "Linux": ["~/.codex/config.toml"],
        "Windows": ["~/.codex/config.toml"],
    },
    AgentType.GEMINI_CLI: {
        # Google Gemini CLI — standard mcpServers JSON format
        "Darwin": ["~/.gemini/settings.json"],
        "Linux": ["~/.gemini/settings.json"],
        "Windows": ["~/.gemini/settings.json"],
    },
    AgentType.GOOSE: {
        # Block Goose — YAML config with extensions section
        "Darwin": ["~/.config/goose/config.yaml"],
        "Linux": ["~/.config/goose/config.yaml"],
        "Windows": ["~/AppData/Roaming/Block/goose/config/config.yaml"],
    },
    AgentType.SNOWFLAKE_CLI: {
        # Snowflake CLI (snow) — TOML connection profiles
        "Darwin": ["~/.snowflake/connections.toml", "~/.snowflake/config.toml"],
        "Linux": ["~/.snowflake/connections.toml", "~/.snowflake/config.toml"],
        "Windows": ["~/.snowflake/connections.toml", "~/.snowflake/config.toml"],
    },
    AgentType.CONTINUE: {
        # Continue.dev VS Code extension
        "Darwin": ["~/.continue/config.json", "~/Library/Application Support/Code/User/globalStorage/continue.continue/config.json"],
        "Linux": ["~/.continue/config.json", "~/.config/Code/User/globalStorage/continue.continue/config.json"],
        "Windows": ["~/.continue/config.json", "~/AppData/Roaming/Code/User/globalStorage/continue.continue/config.json"],
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
    AgentType.JETBRAINS_AI: {
        # JetBrains AI Assistant MCP — global config across all JetBrains IDEs
        # Paths contain version-specific dirs (IntelliJIdea2025.2, PyCharm2025.2, etc.)
        # Also supports ~/.config/github-copilot/intellij/mcp.json for Copilot in JetBrains
        "Darwin": [
            "~/Library/Application Support/JetBrains/*/mcp.json",
            "~/.config/github-copilot/intellij/mcp.json",
        ],
        "Linux": [
            "~/.config/JetBrains/*/mcp.json",
            "~/.config/github-copilot/intellij/mcp.json",
        ],
        "Windows": [
            "~/AppData/Roaming/JetBrains/*/mcp.json",
            "~/.config/github-copilot/intellij/mcp.json",
        ],
    },
    AgentType.JUNIE: {
        # JetBrains Junie coding agent — clean, stable paths
        "Darwin": ["~/.junie/mcp/mcp.json"],
        "Linux": ["~/.junie/mcp/mcp.json"],
        "Windows": ["~/.junie/mcp/mcp.json"],
    },
    AgentType.COPILOT_CLI: {
        # GitHub Copilot CLI (standalone) — ~/.copilot/mcp-config.json
        "Darwin": ["~/.copilot/mcp-config.json"],
        "Linux": ["~/.copilot/mcp-config.json"],
        "Windows": ["~/.copilot/mcp-config.json"],
    },
    AgentType.TABNINE: {
        # Tabnine AI assistant — ~/.tabnine/mcp_servers.json (global)
        "Darwin": ["~/.tabnine/mcp_servers.json"],
        "Linux": ["~/.tabnine/mcp_servers.json"],
        "Windows": ["~/.tabnine/mcp_servers.json"],
    },
    AgentType.SOURCEGRAPH_CODY: {
        # Sourcegraph Cody — VS Code extension + standalone config
        "Darwin": [
            "~/Library/Application Support/Code/User/globalStorage/sourcegraph.cody-ai/mcp.json",
            "~/.cody/mcp.json",
        ],
        "Linux": [
            "~/.config/Code/User/globalStorage/sourcegraph.cody-ai/mcp.json",
            "~/.cody/mcp.json",
        ],
        "Windows": [
            "~/AppData/Roaming/Code/User/globalStorage/sourcegraph.cody-ai/mcp.json",
            "~/.cody/mcp.json",
        ],
    },
    AgentType.AIDER: {
        # Aider AI pair programming — YAML config with mcpServers
        "Darwin": ["~/.aider/mcp.json", "~/.aider.conf.yml"],
        "Linux": ["~/.aider/mcp.json", "~/.aider.conf.yml"],
        "Windows": ["~/.aider/mcp.json", "~/.aider.conf.yml"],
    },
    AgentType.REPLIT_AGENT: {
        # Replit Agent — .replit config or MCP config in workspace
        "Darwin": [],
        "Linux": [],
        "Windows": [],
    },
    AgentType.VOID_EDITOR: {
        # Void editor (open-source Cursor alternative) — uses VS Code-style config
        "Darwin": ["~/.void/mcp.json", "~/Library/Application Support/Void/User/globalStorage/void.mcp/mcp.json"],
        "Linux": ["~/.void/mcp.json", "~/.config/Void/User/globalStorage/void.mcp/mcp.json"],
        "Windows": ["~/.void/mcp.json", "~/AppData/Roaming/Void/User/globalStorage/void.mcp/mcp.json"],
    },
    AgentType.AIDE: {
        # Aide AI IDE (VS Code fork) — standard mcpServers format
        "Darwin": ["~/.aide/mcp.json", "~/Library/Application Support/Aide/User/mcp.json"],
        "Linux": ["~/.aide/mcp.json", "~/.config/Aide/User/mcp.json"],
        "Windows": ["~/.aide/mcp.json", "~/AppData/Roaming/Aide/User/mcp.json"],
    },
    AgentType.TRAE: {
        # Trae AI IDE (ByteDance) — standard mcpServers format
        "Darwin": ["~/.trae/mcp.json", "~/Library/Application Support/Trae/User/mcp.json"],
        "Linux": ["~/.trae/mcp.json", "~/.config/Trae/User/mcp.json"],
        "Windows": ["~/.trae/mcp.json", "~/AppData/Roaming/Trae/User/mcp.json"],
    },
    AgentType.PIECES: {
        # Pieces for Developers — desktop app + VS Code extension
        "Darwin": ["~/Library/Application Support/com.pieces.os/mcp.json", "~/.pieces/mcp.json"],
        "Linux": ["~/.pieces/mcp.json"],
        "Windows": ["~/AppData/Roaming/Pieces/mcp.json", "~/.pieces/mcp.json"],
    },
    AgentType.MCP_CLI: {
        # mcp-cli standalone tool — config in ~/.mcp/
        "Darwin": ["~/.mcp/config.json"],
        "Linux": ["~/.mcp/config.json"],
        "Windows": ["~/.mcp/config.json"],
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
    AgentType.CORTEX_CODE: "cortex",
    AgentType.CODEX_CLI: "codex",
    AgentType.GEMINI_CLI: "gemini",
    AgentType.GOOSE: "goose",
    AgentType.SNOWFLAKE_CLI: "snow",
    AgentType.JUNIE: "junie",
    AgentType.AIDER: "aider",
    AgentType.VOID_EDITOR: "void",
    AgentType.AIDE: "aide",
    AgentType.TRAE: "trae",
    AgentType.MCP_CLI: "mcp",
}

# Project-level config files to search for
PROJECT_CONFIG_FILES = [
    ".mcp.json",
    "mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".openclaw/openclaw.json",
    ".codex/config.toml",
    ".gemini/settings.json",
    ".junie/mcp/mcp.json",
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


# Custom parsers for non-JSON config formats
_CUSTOM_PARSERS: dict[AgentType, str] = {
    AgentType.CODEX_CLI: "toml",
    AgentType.GOOSE: "yaml",
    AgentType.SNOWFLAKE_CLI: "toml",
}


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


def _find_binary(binary_name: str) -> str | None:
    """Find a binary on PATH or in common install locations."""
    found = shutil.which(binary_name)
    if found:
        return found
    # Check common locations not always in PATH
    for extra_dir in ("~/.local/bin", "/usr/local/bin", "~/.cargo/bin"):
        candidate = Path(extra_dir).expanduser() / binary_name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


# Additional install signals beyond binary detection
_INSTALL_SIGNALS: dict[AgentType, list[str]] = {
    AgentType.CORTEX_CODE: ["~/.snowflake/cortex/logs/coco.log"],
}


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
        found = _find_binary(binary_name)
        if not found:
            # Check install signal files (e.g. log files that prove installation)
            for signal in _INSTALL_SIGNALS.get(agent_type, []):
                if Path(signal).expanduser().exists():
                    found = signal
                    break
        if found:
            installed.append(
                Agent(
                    name=agent_type.value,
                    agent_type=agent_type,
                    config_path=f"{binary_name} ({found})",
                    status=AgentStatus.INSTALLED_NOT_CONFIGURED,
                )
            )
    return installed


def discover_global_configs(agent_types: Optional[list[AgentType]] = None) -> list[Agent]:
    """Discover all global MCP client configurations."""
    agents: list[Agent] = []
    sys_platform = get_platform()

    if agent_types is None:
        agent_types = list(CONFIG_LOCATIONS.keys())

    for agent_type in agent_types:
        locations = CONFIG_LOCATIONS.get(agent_type, {})
        platform_paths = locations.get(sys_platform, [])

        for path_str in platform_paths:
            # Handle glob patterns (e.g., JetBrains ~/Library/.../JetBrains/*/mcp.json)
            expanded_base = os.path.expanduser(path_str)
            if "*" in expanded_base:
                resolved_paths = [Path(p).resolve() for p in glob_mod.glob(expanded_base)]
            else:
                resolved_paths = [expand_path(path_str)]

            # Filter out symlinks that resolve outside expected config directories
            # to prevent symlink-based information disclosure attacks.
            safe_paths: list[Path] = []
            for rp in resolved_paths:
                # Skip symlinks whose target differs from the link path's parent tree
                raw_path = Path(os.path.expanduser(path_str)) if "*" not in path_str else rp
                if raw_path.is_symlink() and not rp.is_relative_to(raw_path.parent):
                    logger.warning("Skipping symlink pointing outside parent: %s -> %s", raw_path, rp)
                    continue
                safe_paths.append(rp)

            for config_path in safe_paths:
                if not config_path.exists():
                    continue
                try:
                    servers: list[MCPServer] = []
                    metadata: dict = {}

                    # Cortex Code auxiliary files (permissions, hooks, settings)
                    if agent_type == AgentType.CORTEX_CODE and config_path.name != "mcp.json":
                        metadata = parse_cortex_code_metadata(str(config_path))
                        if metadata:
                            # Attach metadata to existing agent or store for later
                            for a in agents:
                                if a.agent_type == AgentType.CORTEX_CODE:
                                    a.metadata.update(metadata)
                                    break
                        continue

                    # Custom parsers for non-JSON formats
                    if agent_type == AgentType.CODEX_CLI:
                        servers = parse_codex_config(str(config_path))
                    elif agent_type == AgentType.GOOSE:
                        servers = parse_goose_config(str(config_path))
                    elif agent_type == AgentType.SNOWFLAKE_CLI:
                        servers = parse_snowflake_connections(str(config_path))
                    else:
                        # Default JSON parsing
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
                        console.print(f"  [green]✓[/green] Found {agent_type.value} with {len(servers)} MCP server(s): {config_path}")
                except (json.JSONDecodeError, KeyError, TypeError, Exception) as e:
                    console.print(f"  [yellow]⚠[/yellow] Error parsing {config_path}: {e}")

    return agents


def discover_project_configs(project_dir: Optional[str] = None) -> list[Agent]:
    """Discover project-level MCP configurations."""
    agents = []
    search_dir = Path(project_dir) if project_dir else Path.cwd()

    for config_name in PROJECT_CONFIG_FILES:
        config_path = search_dir / config_name
        if config_path.exists():
            try:
                servers: list[MCPServer] = []

                if config_name.endswith(".toml"):
                    # Codex project config
                    servers = parse_codex_config(str(config_path))
                else:
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
                    console.print(f"  [green]✓[/green] Found project config with {len(servers)} MCP server(s): {config_path}")
            except (json.JSONDecodeError, KeyError, TypeError, Exception) as e:
                console.print(f"  [yellow]⚠[/yellow] Error parsing {config_path}: {e}")

    return agents


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
    except (OSError, ValueError):
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
        servers.append(
            MCPServer(
                name=name,
                command="docker",
                args=[],
                transport=TransportType.STDIO,
                config_path=str(registry_path),
            )
        )

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
    except (OSError, ValueError):
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

        packages = [
            Package(
                name=pkg_name,
                version=pkg_version,
                ecosystem="docker",
                is_direct=True,
            )
        ]

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


# ─── MCP process command patterns ─────────────────────────────────────────────
#
# Substrings that, when found in a process's command line, indicate it may be
# an MCP server.  All comparisons are case-insensitive.
_MCP_PROCESS_PATTERNS: tuple[str, ...] = (
    "mcp-server",
    "@modelcontextprotocol/",
    "mcp_server",
    "mcpserver",
    "uvx mcp",
    "npx mcp",
    "python -m mcp",
)

# Env vars that signal an MCP server process (prefix match, uppercase)
_MCP_ENV_SIGNALS: tuple[str, ...] = ("MCP_SERVER", "MCP_PORT", "MCP_TRANSPORT", "MCP_HOST")


def discover_running_processes() -> Optional[Agent]:
    """Discover locally running MCP server processes via psutil.

    Iterates all processes on the host and matches command lines against
    known MCP server patterns (npm/npx @modelcontextprotocol/*, uvx mcp-server-*,
    python -m mcp*, etc.).  Each matching process becomes an MCPServer entry.

    Requires ``psutil`` (``pip install psutil`` or ``agent-bom[runtime]``).
    Returns None if psutil is not installed or no MCP processes are found.
    """
    try:
        import psutil
    except ImportError:
        logger.debug("psutil not installed — skipping process discovery (pip install psutil)")
        return None

    mcp_servers: list[MCPServer] = []

    for proc in psutil.process_iter(["pid", "name", "cmdline", "environ", "cwd"]):
        try:
            info = proc.info
            cmdline: list[str] = info.get("cmdline") or []
            if not cmdline:
                continue

            cmd_str = " ".join(cmdline).lower()
            if not any(pat in cmd_str for pat in _MCP_PROCESS_PATTERNS):
                continue

            # Try to read environment (may raise AccessDenied on some platforms)
            try:
                raw_env: dict[str, str] = info.get("environ") or {}
            except (psutil.AccessDenied, psutil.ZombieProcess):
                raw_env = {}

            # Check env signals too — catch MCP servers not matching cmd patterns
            env_signals = any(k.upper().startswith(_MCP_ENV_SIGNALS) for k in raw_env)
            if not any(pat in cmd_str for pat in _MCP_PROCESS_PATTERNS) and not env_signals:
                continue

            env = sanitize_env_vars({k: str(v) for k, v in raw_env.items()})

            # Derive a human-readable name from the command
            args = cmdline[1:] if len(cmdline) > 1 else []
            # Use the first arg that looks like a package/module name as the server name
            name_parts = [p for p in args if p.startswith("@") or "mcp" in p.lower()]
            server_name = name_parts[0].split("/")[-1] if name_parts else f"process-{info['pid']}"

            # Determine transport from env or args
            transport = TransportType.STDIO
            if "--transport" in args:
                idx = args.index("--transport")
                if idx + 1 < len(args):
                    t = args[idx + 1].lower()
                    if "sse" in t:
                        transport = TransportType.SSE
                    elif "http" in t:
                        transport = TransportType.STREAMABLE_HTTP

            working_dir = info.get("cwd")

            server = MCPServer(
                name=server_name,
                command=cmdline[0],
                args=args,
                env=env,
                transport=transport,
                config_path=f"pid:{info['pid']}",
                working_dir=working_dir,
            )
            mcp_servers.append(server)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if not mcp_servers:
        return None

    return Agent(
        name="running-processes",
        agent_type=AgentType.CUSTOM,
        config_path="psutil://processes",
        mcp_servers=mcp_servers,
        source="process",
    )


def discover_container_labels() -> Optional[Agent]:
    """Discover MCP server containers running locally via Docker.

    Uses ``docker ps`` + ``docker inspect`` (no SDK required) to enumerate
    running containers and identify those whose images, labels, or environment
    variables indicate an MCP server.

    Returns None if Docker is not available or no MCP containers are found.
    """
    if not shutil.which("docker"):
        return None

    try:
        ps_result = subprocess.run(
            ["docker", "ps", "--format", "{{.ID}}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if ps_result.returncode != 0:
        return None

    container_ids = [cid.strip() for cid in ps_result.stdout.splitlines() if cid.strip()]
    if not container_ids:
        return None

    mcp_servers: list[MCPServer] = []

    for cid in container_ids:
        try:
            inspect_result = subprocess.run(
                ["docker", "inspect", "--format", "{{json .}}", cid],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except subprocess.TimeoutExpired:
            continue

        if inspect_result.returncode != 0:
            continue

        try:
            info = json.loads(inspect_result.stdout)
        except (json.JSONDecodeError, ValueError):
            continue

        # Normalise: docker inspect returns a list when called without --format json
        if isinstance(info, list):
            if not info:
                continue
            info = info[0]

        image_name: str = info.get("Config", {}).get("Image", "") or ""
        labels: dict[str, str] = info.get("Config", {}).get("Labels") or {}
        cmd: list[str] = info.get("Config", {}).get("Cmd") or []
        entrypoint: list[str] = info.get("Config", {}).get("Entrypoint") or []

        # Collect raw env list → dict
        raw_env_list: list[str] = info.get("Config", {}).get("Env") or []
        raw_env: dict[str, str] = {}
        for entry in raw_env_list:
            if "=" in entry:
                k, _, v = entry.partition("=")
                raw_env[k] = v

        image_lower = image_name.lower()
        label_vals = " ".join(labels.values()).lower()
        label_keys = " ".join(labels.keys()).lower()
        cmd_str = " ".join(cmd + entrypoint).lower()
        env_keys = " ".join(raw_env.keys()).upper()

        is_mcp = (
            "mcp" in image_lower
            or any(p in image_lower for p in ("modelcontextprotocol", "mcp-server", "mcp_server"))
            or "mcp" in label_vals
            or "mcp" in label_keys
            or "mcp" in cmd_str
            or any(k.startswith(_MCP_ENV_SIGNALS) for k in env_keys.split())
        )

        if not is_mcp:
            continue

        env = sanitize_env_vars(raw_env)

        # Name: prefer label, fall back to image basename, then short container ID
        server_name = (
            labels.get("mcp.name") or labels.get("org.opencontainers.image.title") or image_lower.split("/")[-1].split(":")[0] or cid[:12]
        )

        # Transport: SSE if any port is exposed, else STDIO
        ports = info.get("NetworkSettings", {}).get("Ports") or {}
        transport = TransportType.SSE if ports else TransportType.STDIO
        url: Optional[str] = None
        if ports:
            for port_spec, bindings in ports.items():
                if bindings:
                    host_port = bindings[0].get("HostPort")
                    if host_port:
                        url = f"http://localhost:{host_port}"
                        break

        from agent_bom.models import Package

        packages = [
            Package(
                name=image_name.split(":")[0],
                version=image_name.split(":")[-1] if ":" in image_name else "latest",
                ecosystem="docker",
                is_direct=True,
            )
        ]

        server = MCPServer(
            name=server_name,
            command=f"docker run {image_name}",
            args=[],
            env=env,
            transport=transport,
            url=url,
            packages=packages,
            config_path=f"docker://{cid[:12]}",
        )
        mcp_servers.append(server)

    if not mcp_servers:
        return None

    return Agent(
        name="docker-containers",
        agent_type=AgentType.CUSTOM,
        config_path="docker://localhost",
        mcp_servers=mcp_servers,
        source="container",
    )


# ── Kubernetes MCP CRD / label / env discovery ───────────────────────────────

# MCP signals in pod metadata and container specs
_K8S_MCP_LABELS = ("mcp.server", "mcp-server", "mcp.io/server", "app.kubernetes.io/component=mcp")
_K8S_MCP_IMAGE_PATTERNS = ("mcp-server", "mcp_server", "/mcp:", "-mcp:")
_K8S_MCP_ENV_PREFIX = "MCP_"
_K8S_MCP_CRD_RESOURCE = "mcpservers"  # custom resource: mcpservers.mcp.io


def discover_k8s_mcp_servers(
    namespace: str = "default",
    all_namespaces: bool = False,
    context: Optional[str] = None,
) -> Optional[Agent]:
    """Discover MCP servers declared as Kubernetes pods, services, or CRDs.

    Scans pods for MCP signals (labels, annotations, image names, env vars) and
    optionally queries for ``mcpservers.mcp.io`` custom resources if that CRD
    is installed.  Uses ``kubectl`` — no Python SDK required.

    Args:
        namespace: Kubernetes namespace to query (ignored when ``all_namespaces=True``).
        all_namespaces: Query all namespaces (``kubectl ... -A``).
        context: kubectl context to use (uses current context if ``None``).

    Returns:
        An Agent with ``source="kubernetes"`` or ``None`` if kubectl is absent
        or no MCP pods/CRDs are found.
    """
    if not shutil.which("kubectl"):
        return None

    def _kubectl(*args: str) -> Optional[dict]:
        cmd = ["kubectl", *args]
        if context:
            cmd += ["--context", context]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                return None
            return json.loads(r.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return None

    # ── 1. Pod-level scan ────────────────────────────────────────────────────
    pod_args = ["get", "pods", "-o", "json"]
    if all_namespaces:
        pod_args.append("-A")
    else:
        pod_args += ["-n", namespace]

    pod_data = _kubectl(*pod_args)

    mcp_servers: list[MCPServer] = []
    seen_names: set[str] = set()

    for pod in (pod_data or {}).get("items", []):
        meta = pod.get("metadata", {})
        pod_name = meta.get("name", "unknown")
        pod_ns = meta.get("namespace", namespace)
        labels = meta.get("labels", {})
        annotations = meta.get("annotations", {})
        spec = pod.get("spec", {})

        # Check label signals
        label_str = " ".join(f"{k}={v}" for k, v in labels.items()).lower()
        annotation_keys = " ".join(annotations.keys()).lower()
        has_label_signal = any(sig.lower() in label_str or sig.lower() in annotation_keys for sig in _K8S_MCP_LABELS)

        containers = spec.get("containers", [])
        for container in containers:
            image = container.get("image", "").lower()
            env_vars: list[dict] = container.get("env", [])
            env_names = " ".join(e.get("name", "") for e in env_vars)

            has_image_signal = any(pat in image for pat in _K8S_MCP_IMAGE_PATTERNS)
            has_env_signal = _K8S_MCP_ENV_PREFIX in env_names

            if not (has_label_signal or has_image_signal or has_env_signal):
                continue

            # Determine transport and URL
            transport = TransportType.STDIO
            url = ""
            ports = container.get("ports", [])
            if ports:
                # Assume SSE/HTTP if the container exposes a port
                transport = TransportType.SSE
                port_num = ports[0].get("containerPort", 8000)
                svc_name = labels.get("app", labels.get("app.kubernetes.io/name", pod_name))
                url = f"http://{svc_name}.{pod_ns}.svc.cluster.local:{port_num}"

            # Sanitize env vars
            raw_env = {e.get("name", ""): e.get("value", "") for e in env_vars if e.get("name")}
            env = sanitize_env_vars(raw_env)

            # Build a unique server name
            container_name = container.get("name", "mcp")
            server_name = f"{pod_ns}/{pod_name}/{container_name}"
            if server_name in seen_names:
                continue
            seen_names.add(server_name)

            server = MCPServer(
                name=server_name,
                command="",  # pod containers don't have a local command to launch
                env=env,
                transport=transport,
                url=url,
                config_path=f"k8s://{pod_ns}/{pod_name}",
            )
            mcp_servers.append(server)

    # ── 2. MCP CRD scan (mcpservers.mcp.io) ─────────────────────────────────
    crd_args = ["get", _K8S_MCP_CRD_RESOURCE, "-o", "json"]
    if all_namespaces:
        crd_args.append("-A")
    else:
        crd_args += ["-n", namespace]

    crd_data = _kubectl(*crd_args)

    for item in (crd_data or {}).get("items", []):
        meta = item.get("metadata", {})
        crd_name = meta.get("name", "unknown")
        crd_ns = meta.get("namespace", namespace)
        spec = item.get("spec", {})

        url = spec.get("url", spec.get("endpoint", ""))
        transport = TransportType.SSE if url else TransportType.STDIO
        server_name = f"{crd_ns}/{crd_name}"

        if server_name in seen_names:
            continue
        seen_names.add(server_name)

        server = MCPServer(
            name=server_name,
            command=spec.get("command", ""),
            transport=transport,
            url=url,
            config_path=f"k8s-crd://{crd_ns}/{crd_name}",
        )
        mcp_servers.append(server)

    if not mcp_servers:
        return None

    ns_label = "all-namespaces" if all_namespaces else namespace
    return Agent(
        name=f"kubernetes-mcp/{ns_label}",
        agent_type=AgentType.CUSTOM,
        config_path=f"k8s://{ns_label}",
        mcp_servers=mcp_servers,
        source="kubernetes",
    )


def discover_filesystem_mcps(root: Path) -> list[Agent]:
    """Discover MCP configs inside a mounted filesystem (VM snapshot, container).

    Searches for known MCP client config files relative to every home
    directory found under *root* (e.g. ``/mnt/snapshot/home/user/.cursor/mcp.json``).

    This enables agent → server → package → CVE chain mapping for VM
    disk snapshots without requiring the VM to be running.

    Security: only reads JSON/TOML config files — no execution, no symlink
    traversal outside the root, no environment variable expansion.
    """
    agents: list[Agent] = []
    root = root.resolve()
    if not root.is_dir():
        return agents

    # Collect all home-like directories inside the root
    # Patterns: /home/*/  /root/  /Users/*/  (Linux, macOS layouts)
    home_dirs: list[Path] = []
    for pattern in ["home/*", "root", "Users/*"]:
        home_dirs.extend(p for p in root.glob(pattern) if p.is_dir())
    # Also check root itself (if someone mounted just a home dir)
    home_dirs.append(root)

    # Extract the relative portion of each CONFIG_LOCATIONS path (strip ~/  prefix)
    # and search for them under each home dir
    for agent_type, locations in CONFIG_LOCATIONS.items():
        # Check all platform paths (VM might be a different OS)
        all_paths: set[str] = set()
        for plat_paths in locations.values():
            for p in plat_paths:
                # Strip ~/ prefix to get relative path
                rel = p.lstrip("~").lstrip("/")
                all_paths.add(rel)

        for home in home_dirs:
            for rel_path in all_paths:
                config_path = home / rel_path
                # Security: ensure resolved path stays inside root
                try:
                    resolved = config_path.resolve()
                    if not resolved.is_relative_to(root):
                        logger.warning("Skipping path outside root: %s", config_path)
                        continue
                except (OSError, ValueError):
                    continue

                if not config_path.exists() or not config_path.is_file():
                    continue

                try:
                    servers: list[MCPServer] = []
                    if config_path.suffix == ".json":
                        config_data = json.loads(config_path.read_text(encoding="utf-8"))
                        servers = parse_mcp_config(config_data, str(config_path))
                    elif config_path.suffix == ".toml" and agent_type == AgentType.CODEX_CLI:
                        servers = parse_codex_config(str(config_path))

                    if servers:
                        agent = Agent(
                            name=f"{agent_type.value}@{home.name}",
                            agent_type=agent_type,
                            config_path=str(config_path),
                            mcp_servers=servers,
                            status=AgentStatus.CONFIGURED,
                        )
                        agents.append(agent)
                        logger.info(
                            "Discovered %s with %d server(s) in filesystem: %s",
                            agent_type.value,
                            len(servers),
                            config_path,
                        )
                except Exception:
                    logger.debug("Failed to parse %s", config_path, exc_info=True)

    return agents


def discover_all(
    project_dir: Optional[str] = None,
    dynamic: bool = False,
    dynamic_max_depth: int = 4,
    include_processes: bool = False,
    include_containers: bool = False,
    include_k8s_mcp: bool = False,
    k8s_namespace: str = "default",
    k8s_all_namespaces: bool = False,
    k8s_context: Optional[str] = None,
) -> list[Agent]:
    """Run full discovery: global configs + project configs + CLI agents.

    Args:
        project_dir: Optional project directory to scan.
        dynamic: Enable dynamic content-based discovery layer.
        dynamic_max_depth: Maximum depth for dynamic filesystem scanning.
        include_processes: Also scan running host processes for MCP servers (psutil).
        include_containers: Also scan running Docker containers for MCP servers.
        include_k8s_mcp: Scan Kubernetes cluster for MCP pods and CRDs (kubectl).
        k8s_namespace: Kubernetes namespace to query (default: "default").
        k8s_all_namespaces: Query all Kubernetes namespaces.
        k8s_context: kubectl context to use (uses current context if None).
    """
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
            f"  [green]✓[/green] Found {len(compose_agent.mcp_servers)} MCP server(s) in Docker Compose: {compose_agent.config_path}"
        )
        agents.append(compose_agent)

    # ToolHive CLI-based discovery
    thv_agent = discover_toolhive()
    if thv_agent:
        if thv_agent.mcp_servers:
            console.print(f"  [green]✓[/green] Found toolhive with {len(thv_agent.mcp_servers)} MCP server(s) (via thv list)")
        else:
            console.print("  [dim]  toolhive: installed but not configured[/dim]")
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
            console.print("  [dim]  docker-mcp: installed but not configured[/dim]")
        agents.append(docker_agent)

    # Running process discovery (opt-in, requires psutil)
    if include_processes:
        proc_agent = discover_running_processes()
        if proc_agent:
            console.print(f"  [green]✓[/green] Found {len(proc_agent.mcp_servers)} MCP server process(es) via psutil")
            agents.append(proc_agent)
        else:
            console.print("  [dim]  process scan: no MCP server processes found[/dim]")

    # Docker container discovery (opt-in)
    if include_containers:
        container_agent = discover_container_labels()
        if container_agent:
            console.print(f"  [green]✓[/green] Found {len(container_agent.mcp_servers)} MCP container(s) via docker inspect")
            agents.append(container_agent)
        else:
            console.print("  [dim]  container scan: no MCP containers found (or docker not running)[/dim]")

    # Kubernetes MCP pod/CRD discovery (opt-in)
    if include_k8s_mcp:
        k8s_agent = discover_k8s_mcp_servers(
            namespace=k8s_namespace,
            all_namespaces=k8s_all_namespaces,
            context=k8s_context,
        )
        if k8s_agent:
            console.print(f"  [green]✓[/green] Found {len(k8s_agent.mcp_servers)} MCP server(s) in Kubernetes (pods + CRDs)")
            agents.append(k8s_agent)
        else:
            console.print("  [dim]  k8s-mcp scan: no MCP pods/CRDs found (or kubectl not available)[/dim]")

    # Detect installed-but-not-configured agents
    discovered_types = {a.agent_type for a in agents}
    installed_agents = detect_installed_agents(discovered_types)
    for ia in installed_agents:
        console.print(f"  [dim]  {ia.name}: installed but not configured[/dim]")
    agents.extend(installed_agents)

    # Dynamic content-based discovery layer (opt-in)
    if dynamic:
        from pathlib import Path as _DynPath

        from agent_bom.discovery.dynamic import discover_dynamic, merge_discoveries

        console.print("\n  [bold cyan]🔎 Running dynamic discovery...[/bold cyan]")
        known_paths = {a.config_path for a in agents if a.config_path}
        dyn_result = discover_dynamic(
            root=_DynPath(project_dir) if project_dir else _DynPath.cwd(),
            max_depth=dynamic_max_depth,
            exclude_paths=known_paths,
        )
        if dyn_result.agents:
            console.print(
                f"  [green]✓[/green] Dynamic discovery found {len(dyn_result.agents)} additional config(s) "
                f"({dyn_result.scanned_paths} files scanned, {dyn_result.elapsed_ms:.0f}ms)"
            )
        agents = merge_discoveries(agents, dyn_result.agents)

    configured = [a for a in agents if a.status == AgentStatus.CONFIGURED]
    if not configured and not installed_agents:
        console.print("  [yellow]No MCP configurations found.[/yellow]")
    else:
        total_servers = sum(len(a.mcp_servers) for a in configured)
        console.print(f"\n  [bold]Found {len(configured)} configured agent(s) with {total_servers} MCP server(s) total.[/bold]")
        if installed_agents:
            console.print(f"  [dim]{len(installed_agents)} additional agent(s) installed but not configured.[/dim]")

    return agents
