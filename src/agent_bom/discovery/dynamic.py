"""Dynamic MCP configuration discovery — content-based, environment-based.

Supplements the hardcoded path-based discovery in ``discovery/__init__.py``
by scanning the filesystem for files that *look like* MCP configs based on
their content structure, and by checking environment variables that may
reference MCP configuration files.

All operations are **read-only** and **safe** — no subprocess calls, no
network access, bounded filesystem scanning with skip-lists and depth limits.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from agent_bom.models import Agent, AgentStatus, AgentType, MCPServer, TransportType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------


@dataclass
class DynamicDiscoveryResult:
    """Result container for dynamic discovery with provenance tracking."""

    agents: list[Agent] = field(default_factory=list)
    scanned_paths: int = 0
    matched_paths: int = 0
    skipped_paths: int = 0
    env_vars_checked: int = 0
    elapsed_ms: float = 0.0


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Directories to always skip during filesystem scanning
SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".cargo",
        ".npm",
        "dist",
        "build",
        ".next",
    }
)

# Home-directory glob patterns (expanded relative to ~/)
HOME_GLOB_PATTERNS: list[str] = [
    ".config/*/mcp.json",
    ".config/*/mcp*.json",
    ".*/mcp.json",
    ".*/mcp-config.json",
]

# Project-directory glob patterns (expanded relative to project root)
PROJECT_GLOB_PATTERNS: list[str] = [
    "mcp.json",
    ".mcp.json",
    "mcp-config.json",
    ".mcp/*.json",
    "*/mcp.json",
    "*/.mcp.json",
    "*/mcp-config.json",
]

# Top-level JSON keys that identify an MCP config
MCP_JSON_SIGNATURES: frozenset[str] = frozenset({"mcpServers", "mcp_servers", "servers", "context_servers"})

# Both keys present in a nested object → likely an MCP stdio server definition
MCP_STDIO_KEYS: frozenset[str] = frozenset({"command", "args"})

# Environment variable prefixes that may reference MCP config files
MCP_ENV_PREFIXES: tuple[str, ...] = (
    "MCP_",
    "CLAUDE_",
    "CURSOR_",
    "WINDSURF_",
    "CORTEX_",
    "CLINE_",
    "CODEX_",
    "GEMINI_",
    "GOOSE_",
)

# Max file size to attempt parsing (skip large files)
_MAX_FILE_SIZE = 512 * 1024  # 512 KB


# ---------------------------------------------------------------------------
# Filesystem scanning
# ---------------------------------------------------------------------------


def _scan_filesystem(
    base_dir: Path,
    patterns: list[str],
    max_depth: int,
    exclude_paths: set[str],
) -> list[Path]:
    """Glob-scan a directory for potential MCP config files.

    Respects *max_depth* to avoid descending into deep trees and
    skips well-known heavy directories (node_modules, .git, …).
    Returns candidate paths that match filename patterns.
    """
    candidates: list[Path] = []
    base_resolved = base_dir.resolve()

    for pattern in patterns:
        try:
            for match in base_resolved.glob(pattern):
                if not match.is_file():
                    continue
                resolved = str(match.resolve())
                if resolved in exclude_paths:
                    continue
                # Depth check
                try:
                    rel = match.resolve().relative_to(base_resolved)
                    if len(rel.parts) > max_depth:
                        continue
                except ValueError:
                    continue
                # Skip banned directories
                if any(part in SKIP_DIRS for part in rel.parts):
                    continue
                # Skip overly large files
                try:
                    if match.stat().st_size > _MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue
                candidates.append(match)
        except (OSError, PermissionError):
            logger.debug("Permission denied scanning %s with pattern %s", base_dir, pattern)

    # Deduplicate by resolved path
    seen: set[str] = set()
    deduped: list[Path] = []
    for p in candidates:
        rp = str(p.resolve())
        if rp not in seen:
            seen.add(rp)
            deduped.append(p)
    return deduped


# ---------------------------------------------------------------------------
# Content-based MCP config detection
# ---------------------------------------------------------------------------


def _detect_mcp_config(path: Path) -> Optional[Agent]:
    """Content-based detection: read a file and determine if it's an MCP config.

    Supports JSON with ``mcpServers``/``mcp_servers``/``servers``/``context_servers``
    top-level keys. Returns an ``Agent`` with CUSTOM type if detected, else ``None``.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return None

    # Try JSON first (most common MCP config format)
    if path.suffix in (".json", ""):
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return _detect_json_mcp(path, data)
        except (json.JSONDecodeError, ValueError):
            pass

    # Try TOML (Codex CLI, Snowflake CLI)
    if path.suffix in (".toml", ""):
        agent = _detect_toml_mcp(path, text)
        if agent:
            return agent

    # Try YAML (Goose, Docker MCP)
    if path.suffix in (".yaml", ".yml", ""):
        agent = _detect_yaml_mcp(path, text)
        if agent:
            return agent

    return None


def _detect_json_mcp(path: Path, data: dict) -> Optional[Agent]:
    """Check if a parsed JSON dict looks like an MCP config and extract servers."""
    # Check for MCP signature keys
    matched_key = None
    for key in MCP_JSON_SIGNATURES:
        if key in data:
            matched_key = key
            break

    if matched_key is None:
        # Fallback: check if top-level has objects with command+args (loose detection)
        for _key, val in data.items():
            if isinstance(val, dict) and MCP_STDIO_KEYS.issubset(val.keys()):
                matched_key = _key
                break

    if matched_key is None:
        return None

    # Normalize: parse_mcp_config expects "mcpServers" or "servers" or "context_servers"
    # but dynamic discovery may also find "mcp_servers" (snake_case variant)
    normalized = data
    if matched_key == "mcp_servers" and "mcpServers" not in data:
        normalized = dict(data)
        normalized["mcpServers"] = normalized.pop("mcp_servers")

    # Reuse the existing parser from discovery/__init__.py
    try:
        from agent_bom.discovery import parse_mcp_config

        servers = parse_mcp_config(normalized, str(path))
    except Exception:  # noqa: BLE001
        servers = _extract_servers_simple(data, matched_key, str(path))

    if not servers:
        return None

    return Agent(
        name=f"dynamic:{path.stem}",
        agent_type=AgentType.CUSTOM,
        config_path=str(path.resolve()),
        mcp_servers=servers,
        status=AgentStatus.CONFIGURED,
        source="dynamic",
    )


def _extract_servers_simple(data: dict, key: str, config_path: str) -> list[MCPServer]:
    """Simple fallback server extraction without security validation."""
    servers: list[MCPServer] = []
    raw = data.get(key, {})

    if isinstance(raw, list):
        items = {item.get("name", f"server-{i}"): item for i, item in enumerate(raw) if isinstance(item, dict)}
    elif isinstance(raw, dict):
        items = raw
    else:
        return servers

    for name, sdef in items.items():
        if not isinstance(sdef, dict):
            continue
        command = sdef.get("command", "")
        args = sdef.get("args", [])
        url = sdef.get("url") or sdef.get("uri")

        transport = TransportType.STDIO
        if url:
            transport = TransportType.SSE if "sse" in str(url).lower() else TransportType.STREAMABLE_HTTP

        servers.append(
            MCPServer(
                name=name,
                command=str(command) if command else "",
                args=args if isinstance(args, list) else [str(args)],
                transport=transport,
                url=url,
                config_path=config_path,
            )
        )
    return servers


def _detect_toml_mcp(path: Path, text: str) -> Optional[Agent]:
    """Check if a TOML file contains ``[mcp_servers]`` sections."""
    # Lightweight check without importing tomllib — look for section header
    if "[mcp_servers" not in text and "[mcp-servers" not in text:
        return None

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return None

    try:
        data = tomllib.loads(text)
    except Exception:  # noqa: BLE001
        return None

    mcp_section = data.get("mcp_servers") or data.get("mcp-servers")
    if not isinstance(mcp_section, dict):
        return None

    servers: list[MCPServer] = []
    for name, sdef in mcp_section.items():
        if not isinstance(sdef, dict):
            continue
        command = sdef.get("command", "")
        args = sdef.get("args", [])
        url = sdef.get("url") or sdef.get("uri")
        transport = TransportType.STDIO
        if url:
            transport = TransportType.STREAMABLE_HTTP

        servers.append(
            MCPServer(
                name=name,
                command=str(command) if command else "",
                args=args if isinstance(args, list) else [str(args)],
                transport=transport,
                url=url,
                config_path=str(path),
            )
        )

    if not servers:
        return None

    return Agent(
        name=f"dynamic:{path.stem}",
        agent_type=AgentType.CUSTOM,
        config_path=str(path.resolve()),
        mcp_servers=servers,
        status=AgentStatus.CONFIGURED,
        source="dynamic",
    )


def _detect_yaml_mcp(path: Path, text: str) -> Optional[Agent]:
    """Check if a YAML file contains ``mcp_servers:`` key."""
    if "mcp_servers:" not in text and "mcpServers:" not in text:
        return None

    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return None

    try:
        data = yaml.safe_load(text)
    except Exception:  # noqa: BLE001
        return None

    if not isinstance(data, dict):
        return None

    mcp_section = data.get("mcp_servers") or data.get("mcpServers")
    if not isinstance(mcp_section, dict):
        return None

    servers: list[MCPServer] = []
    for name, sdef in mcp_section.items():
        if not isinstance(sdef, dict):
            continue
        command = sdef.get("command", "")
        args = sdef.get("args", [])

        servers.append(
            MCPServer(
                name=name,
                command=str(command) if command else "",
                args=args if isinstance(args, list) else [str(args)],
                config_path=str(path),
            )
        )

    if not servers:
        return None

    return Agent(
        name=f"dynamic:{path.stem}",
        agent_type=AgentType.CUSTOM,
        config_path=str(path.resolve()),
        mcp_servers=servers,
        status=AgentStatus.CONFIGURED,
        source="dynamic",
    )


# ---------------------------------------------------------------------------
# Environment variable scanning
# ---------------------------------------------------------------------------


def _scan_environment(exclude_paths: set[str]) -> list[Agent]:
    """Scan environment variables for MCP-related config file references.

    Checks variables whose names start with known MCP-related prefixes.
    If the value looks like a file path and the file contains MCP config
    structure, an Agent is returned.
    """
    agents: list[Agent] = []
    checked = 0

    for name, value in os.environ.items():
        if not any(name.startswith(prefix) for prefix in MCP_ENV_PREFIXES):
            continue
        checked += 1

        # Value must look like a file path
        if not value or len(value) > 1024:
            continue
        path = Path(value).expanduser()
        if not path.is_file():
            continue
        resolved = str(path.resolve())
        if resolved in exclude_paths:
            continue

        agent = _detect_mcp_config(path)
        if agent:
            agent.name = f"env:{name}"
            agent.source = "environment"
            agents.append(agent)
            exclude_paths.add(resolved)

    return agents


# ---------------------------------------------------------------------------
# Merge / deduplication
# ---------------------------------------------------------------------------


def merge_discoveries(
    known: list[Agent],
    dynamic: list[Agent],
) -> list[Agent]:
    """Merge known-client and dynamic discovery results, deduplicating by config_path.

    Known-client results take precedence (they have the correct AgentType).
    Dynamic results only add agents whose config_path is not already present.
    """
    known_paths: set[str] = set()
    for agent in known:
        if agent.config_path:
            try:
                known_paths.add(str(Path(agent.config_path).expanduser().resolve()))
            except (OSError, ValueError):
                known_paths.add(agent.config_path)

    merged = list(known)
    for agent in dynamic:
        if not agent.config_path:
            merged.append(agent)
            continue
        try:
            resolved = str(Path(agent.config_path).resolve())
        except (OSError, ValueError):
            resolved = agent.config_path
        if resolved not in known_paths:
            merged.append(agent)
            known_paths.add(resolved)

    return merged


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def discover_dynamic(
    root: Optional[Path] = None,
    max_depth: int = 4,
    scan_home: bool = True,
    scan_project: bool = True,
    scan_env: bool = True,
    exclude_paths: Optional[set[str]] = None,
) -> DynamicDiscoveryResult:
    """Main entry point for dynamic MCP config discovery.

    Runs filesystem glob scanning (home + project directories) and
    environment variable scanning to find MCP configs that the
    hardcoded path-based discovery may have missed.

    Args:
        root: Project root directory (defaults to CWD).
        max_depth: Maximum directory depth for glob scanning.
        scan_home: Scan home directory glob patterns.
        scan_project: Scan project directory glob patterns.
        scan_env: Scan environment variables for MCP references.
        exclude_paths: Set of resolved path strings to skip (already discovered).

    Returns:
        DynamicDiscoveryResult with discovered agents and scan statistics.
    """
    t0 = time.monotonic()
    exclude = set(exclude_paths) if exclude_paths else set()
    result = DynamicDiscoveryResult()

    all_candidates: list[Path] = []

    # 1. Home directory scanning
    if scan_home:
        home = Path.home()
        if home.exists():
            candidates = _scan_filesystem(home, HOME_GLOB_PATTERNS, max_depth, exclude)
            all_candidates.extend(candidates)

    # 2. Project directory scanning
    if scan_project:
        project = root or Path.cwd()
        if project.exists():
            candidates = _scan_filesystem(project, PROJECT_GLOB_PATTERNS, max_depth, exclude)
            all_candidates.extend(candidates)

    result.scanned_paths = len(all_candidates)

    # 3. Content-based detection
    for path in all_candidates:
        agent = _detect_mcp_config(path)
        if agent:
            result.agents.append(agent)
            result.matched_paths += 1
            # Add to exclude set so env scanning doesn't duplicate
            exclude.add(str(path.resolve()))
        else:
            result.skipped_paths += 1

    # 4. Environment variable scanning
    if scan_env:
        env_agents = _scan_environment(exclude)
        result.agents.extend(env_agents)
        result.env_vars_checked = sum(1 for name in os.environ if any(name.startswith(p) for p in MCP_ENV_PREFIXES))

    result.elapsed_ms = (time.monotonic() - t0) * 1000
    return result
