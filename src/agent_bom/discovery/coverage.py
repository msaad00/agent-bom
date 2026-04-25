"""Discovery coverage and supported-client matrix helpers."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from agent_bom.models import Agent, AgentType


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
    entries = _path_coverage_entries(path_entries)
    return {
        "platform": platform,
        "supported_client_count": len(supported),
        "supported_clients": [client.to_dict() for client in supported],
        "path_count": len(entries),
        "found_path_count": sum(1 for entry in entries if entry["exists"]),
        "paths": entries,
        "completeness": discovery_completeness_summary(path_entries),
    }


def discovery_completeness_summary(
    path_entries: list[tuple[str, str]],
    *,
    agents: list[Agent] | None = None,
) -> dict[str, Any]:
    """Build non-secret inventory completeness telemetry.

    Completeness is intentionally shape-based. It records whether expected
    config sources were present, whether they could be parsed, and how many MCP
    server entries were discovered from those sources. It never returns raw
    config contents, env values, args, or credential material.
    """

    actual_by_path = _actual_servers_by_config_path(agents or [])
    sources = []
    for entry in _path_coverage_entries(path_entries):
        expanded = _expanded_path(entry["path"])
        source = {
            **entry,
            "expanded": str(expanded) if not entry["path"].startswith(".") else entry["path"],
            "status": "missing",
            "expected_count": 0,
            "actual_count": actual_by_path.get(str(expanded), 0),
            "skipped_count": 0,
            "blocked_count": 0,
            "confidence": "high",
        }
        if not entry["exists"]:
            sources.append(source)
            continue

        expected = _expected_server_count_from_path(expanded)
        source.update(expected)
        source["actual_count"] = actual_by_path.get(str(expanded), 0)
        if source["status"] == "present" and source["expected_count"] and source["actual_count"] < source["expected_count"]:
            source["status"] = "under_discovered"
            source["confidence"] = "medium"
        sources.append(source)

    expected_known = [s["expected_count"] for s in sources if isinstance(s.get("expected_count"), int)]
    parse_error_count = sum(1 for s in sources if s["status"] == "parse_error")
    under_discovered_count = sum(1 for s in sources if s["status"] == "under_discovered")
    found_sources = sum(1 for s in sources if s["exists"])
    missing_sources = sum(1 for s in sources if not s["exists"])
    actual_server_count = sum(s["actual_count"] for s in sources)
    confidence = "high"
    if parse_error_count:
        confidence = "low"
    elif under_discovered_count or any(s["status"] == "present_unclassified" for s in sources):
        confidence = "medium"

    return {
        "path_count": len(sources),
        "found_source_count": found_sources,
        "missing_source_count": missing_sources,
        "parse_error_count": parse_error_count,
        "under_discovered_source_count": under_discovered_count,
        "expected_server_count": sum(expected_known),
        "actual_server_count": actual_server_count,
        "confidence": confidence,
        "sources": sources,
    }


def _path_coverage_entries(path_entries: list[tuple[str, str]]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for client, path in path_entries:
        is_project_relative = path.startswith(".")
        exists = Path(path).exists() if is_project_relative else Path(path).expanduser().exists()
        entries.append(
            {
                "client": client,
                "path": path,
                "exists": exists,
                "path_kind": "project_relative" if is_project_relative else "user_config",
            }
        )
    return entries


def _expanded_path(path: str) -> Path:
    if path.startswith("."):
        return Path(path).resolve()
    return Path(path).expanduser().resolve()


def _actual_servers_by_config_path(agents: list[Agent]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for agent in agents:
        try:
            key = str(Path(agent.config_path).expanduser().resolve())
        except OSError:
            key = agent.config_path
        counts[key] = counts.get(key, 0) + len(agent.mcp_servers)
    return counts


def _expected_server_count_from_path(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {"status": "unreadable", "expected_count": None, "skipped_count": 1, "confidence": "low"}
    try:
        data = _parse_config_shape(path, text)
    except Exception:  # noqa: BLE001 - telemetry must not leak parser internals
        return {"status": "parse_error", "expected_count": None, "skipped_count": 1, "confidence": "low"}
    if not isinstance(data, dict):
        return {"status": "present_unclassified", "expected_count": None, "confidence": "medium"}
    count = _count_mcp_server_entries(data)
    if count is None:
        return {"status": "present_unclassified", "expected_count": None, "confidence": "medium"}
    return {"status": "present", "expected_count": count, "confidence": "high"}


def _parse_config_shape(path: Path, text: str) -> Any:
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        import yaml  # type: ignore[import-untyped]

        return yaml.safe_load(text) or {}
    if suffix == ".toml":
        try:
            import tomllib
        except ModuleNotFoundError:  # pragma: no cover - Python <3.11 fallback
            import tomli as tomllib  # type: ignore[import-not-found,no-redef]

        return tomllib.loads(text)
    return json.loads(text)


def _count_mcp_server_entries(data: dict[str, Any]) -> int | None:
    counts: list[int] = []
    for key in ("mcpServers", "mcp_servers", "servers", "context_servers"):
        raw = data.get(key)
        if isinstance(raw, dict):
            counts.append(len(raw))
        elif isinstance(raw, list):
            counts.append(sum(1 for item in raw if isinstance(item, dict)))

    projects = data.get("projects")
    if isinstance(projects, dict):
        for project in projects.values():
            if isinstance(project, dict):
                mcp_servers = project.get("mcpServers")
                if isinstance(mcp_servers, dict):
                    counts.append(len(mcp_servers))
                elif isinstance(mcp_servers, list):
                    counts.append(sum(1 for item in mcp_servers if isinstance(item, dict)))

    return sum(counts) if counts else None
