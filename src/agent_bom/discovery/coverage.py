"""Discovery coverage and supported-client matrix helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from agent_bom.models import AgentType


@dataclass(frozen=True)
class SupportedClient:
    """Code-backed discovery support for one client or surface."""

    agent_type: str
    display_name: str
    support_level: str
    parser: str
    notes: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


_DISPLAY_NAMES: dict[AgentType, str] = {
    AgentType.CLAUDE_DESKTOP: "Claude Desktop",
    AgentType.CLAUDE_CODE: "Claude Code",
    AgentType.CURSOR: "Cursor",
    AgentType.WINDSURF: "Windsurf",
    AgentType.CLINE: "Cline",
    AgentType.VSCODE_COPILOT: "VS Code Copilot Agent Mode",
    AgentType.CORTEX_CODE: "Snowflake Cortex Code",
    AgentType.CODEX_CLI: "OpenAI Codex CLI",
    AgentType.GEMINI_CLI: "Google Gemini CLI",
    AgentType.GOOSE: "Block Goose",
    AgentType.SNOWFLAKE_CLI: "Snowflake CLI",
    AgentType.CONTINUE: "Continue.dev",
    AgentType.ZED: "Zed",
    AgentType.OPENCLAW: "OpenClaw",
    AgentType.ROO_CODE: "Roo Code",
    AgentType.AMAZON_Q: "Amazon Q Developer",
    AgentType.DOCKER_MCP: "Docker MCP Toolkit",
    AgentType.JETBRAINS_AI: "JetBrains AI Assistant",
    AgentType.JUNIE: "JetBrains Junie",
    AgentType.COPILOT_CLI: "GitHub Copilot CLI",
    AgentType.TABNINE: "Tabnine",
    AgentType.SOURCEGRAPH_CODY: "Sourcegraph Cody",
    AgentType.AIDER: "Aider",
    AgentType.REPLIT_AGENT: "Replit Agent",
    AgentType.VOID_EDITOR: "Void Editor",
    AgentType.AIDE: "Aide",
    AgentType.TRAE: "Trae",
    AgentType.PIECES: "Pieces for Developers",
    AgentType.MCP_CLI: "mcp-cli",
}

_PARSER_OVERRIDES: dict[AgentType, str] = {
    AgentType.CODEX_CLI: "parse_codex_config",
    AgentType.GOOSE: "parse_goose_config",
    AgentType.SNOWFLAKE_CLI: "parse_snowflake_connections",
    AgentType.DOCKER_MCP: "parse_docker_mcp_catalog",
    AgentType.CORTEX_CODE: "parse_mcp_config + Cortex permissions/hooks audit",
}

_NOTES: dict[AgentType, str] = {
    AgentType.DOCKER_MCP: "Catalog/registry paths are checked separately from standard per-platform config paths.",
    AgentType.REPLIT_AGENT: "Workspace-oriented discovery; no global config path is expected.",
}


def supported_clients() -> list[SupportedClient]:
    """Return the first-class client discovery matrix backed by AgentType."""

    from agent_bom.discovery import CONFIG_LOCATIONS

    clients: list[SupportedClient] = []
    for agent_type in AgentType:
        if agent_type is AgentType.CUSTOM:
            continue
        paths = CONFIG_LOCATIONS.get(agent_type, {})
        has_config_paths = any(paths.get(platform) for platform in ("Darwin", "Linux", "Windows"))
        support_level = "config_paths" if has_config_paths else "dynamic_or_workspace"
        clients.append(
            SupportedClient(
                agent_type=agent_type.value,
                display_name=_DISPLAY_NAMES.get(agent_type, agent_type.value),
                support_level=support_level,
                parser=_PARSER_OVERRIDES.get(agent_type, "parse_mcp_config"),
                notes=_NOTES.get(agent_type, ""),
            )
        )
    return clients


def discovery_coverage_summary(platform: str, path_entries: list[tuple[str, str]]) -> dict[str, Any]:
    """Build non-secret coverage telemetry for discovery path inspection."""

    supported = supported_clients()
    entries = []
    found_paths = 0
    for client, path in path_entries:
        is_project_relative = path.startswith(".")
        exists = Path(path).exists() if is_project_relative else Path(path).expanduser().exists()
        found_paths += int(exists)
        entries.append(
            {
                "client": client,
                "path": path,
                "exists": exists,
                "path_kind": "project_relative" if is_project_relative else "user_config",
            }
        )
    return {
        "platform": platform,
        "supported_client_count": len(supported),
        "supported_clients": [client.to_dict() for client in supported],
        "path_count": len(entries),
        "found_path_count": found_paths,
        "paths": entries,
    }
