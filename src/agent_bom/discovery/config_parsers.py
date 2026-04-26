"""Config file parsers for MCP client discovery.

Each parser converts a specific config format (JSON, TOML, YAML) into
MCPServer objects.  Security auditors for Cortex Code permissions and
hooks are also included here.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Optional

import toml  # type: ignore[import-untyped]
import yaml  # type: ignore[import-untyped]
from rich.console import Console
from rich.markup import escape

from agent_bom.models import MCPServer, TransportType
from agent_bom.security import (
    SecurityError,
    sanitize_env_vars,
    sanitize_log_label,
    validate_mcp_server_config,
)

console = Console(stderr=True)
logger = logging.getLogger(__name__)


def _display_label(value: object, max_len: int = 500) -> str:
    return escape(sanitize_log_label(value, max_len=max_len))


def _string_field(value: object) -> str:
    return value if isinstance(value, str) else ""


def _args_field(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


# ---------------------------------------------------------------------------
# JSON config parsers
# ---------------------------------------------------------------------------


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
            warning_msg = f"Blocked insecure server '{sanitize_log_label(name)}': {sanitize_log_label(e)}"
            logger.warning(warning_msg)
            console.print(f"[yellow]⚠️  {_display_label(warning_msg)}[/yellow]")
            # Include blocked server in report for visibility — no silent skips
            blocked_server = MCPServer(
                name=name,
                command=_string_field(server_def.get("command", "")),
                config_path=config_path,
                security_blocked=True,
                security_warnings=[str(e)],
            )
            servers.append(blocked_server)
            continue

        # Determine transport type
        # VS Code native format uses "type" field + "uri"; standard format uses "url"
        transport = TransportType.STDIO
        url = None
        vscode_type = server_def.get("type", "")
        if vscode_type == "sse":
            transport = TransportType.SSE
            url = _string_field(server_def.get("uri") or server_def.get("url"))
        elif vscode_type == "http":
            transport = TransportType.STREAMABLE_HTTP
            url = _string_field(server_def.get("uri") or server_def.get("url"))
        elif "url" in server_def or "uri" in server_def:
            url = _string_field(server_def.get("url") or server_def.get("uri"))
            if url and "sse" in url.lower():
                transport = TransportType.SSE
            else:
                transport = TransportType.STREAMABLE_HTTP

        command = _string_field(server_def.get("command", ""))
        args = _args_field(server_def.get("args", []))
        raw_env = server_def.get("env", {})

        # ✅ Security: redact credential values before storing in MCPServer
        # Only env var NAMES appear in reports — values are replaced with ***REDACTED***
        env = sanitize_env_vars(raw_env) if isinstance(raw_env, dict) else {}

        server = MCPServer(
            name=name,
            command=command,
            args=args,
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
            project_servers = parse_mcp_config({"mcpServers": mcp_servers}, config_path)
            for s in project_servers:
                s.working_dir = project_path
            servers.extend(project_servers)
    return servers


# ---------------------------------------------------------------------------
# TOML / YAML config parsers
# ---------------------------------------------------------------------------


def parse_codex_config(config_path: str) -> list[MCPServer]:
    """Parse OpenAI Codex CLI TOML config with [mcp_servers.*] tables.

    Supports both stdio (command/args) and HTTP (url/bearer_token_env_var) transports.
    """
    try:
        data = toml.load(config_path)
    except Exception:  # noqa: BLE001 — toml libraries raise varied error types
        return []

    mcp_section = data.get("mcp_servers", {})
    if not isinstance(mcp_section, dict):
        return []

    servers: list[MCPServer] = []
    for name, server_def in mcp_section.items():
        if not isinstance(server_def, dict):
            continue
        if server_def.get("enabled") is False:
            continue

        # Determine transport
        transport = TransportType.STDIO
        url = _string_field(server_def.get("url"))
        command = _string_field(server_def.get("command", ""))
        args = _args_field(server_def.get("args", []))

        if url:
            transport = TransportType.SSE if "sse" in url.lower() else TransportType.STREAMABLE_HTTP

        raw_env = server_def.get("env", {})
        env = sanitize_env_vars(raw_env) if isinstance(raw_env, dict) else {}

        # Bearer token env var → track as credential
        bearer_var = _string_field(server_def.get("bearer_token_env_var"))
        if bearer_var:
            env[bearer_var] = "***REDACTED***"

        server = MCPServer(
            name=name,
            command=command,
            args=args,
            env=env,
            transport=transport,
            url=url,
            config_path=config_path,
        )
        servers.append(server)

    return servers


def parse_goose_config(config_path: str) -> list[MCPServer]:
    """Parse Block Goose YAML config with extensions section.

    Extensions use type: stdio (cmd/args) or type: streamable_http (uri).
    """
    try:
        with open(config_path) as f:
            data = yaml.safe_load(f)
    except (OSError, ValueError):
        return []

    if not isinstance(data, dict):
        return []

    extensions = data.get("extensions", {})
    if not isinstance(extensions, dict):
        return []

    servers: list[MCPServer] = []
    for name, ext_def in extensions.items():
        if not isinstance(ext_def, dict):
            continue
        if ext_def.get("enabled") is False:
            continue
        ext_type = ext_def.get("type", "")
        if ext_type == "builtin":
            continue  # Skip bundled extensions

        transport = TransportType.STDIO
        url = ext_def.get("uri")
        command = ext_def.get("cmd", "")
        args = ext_def.get("args", [])

        if ext_type == "streamable_http" or ext_type == "sse":
            transport = TransportType.SSE if ext_type == "sse" else TransportType.STREAMABLE_HTTP

        raw_env = ext_def.get("envs", {})
        env = sanitize_env_vars(raw_env) if isinstance(raw_env, dict) else {}

        server = MCPServer(
            name=ext_def.get("name", name) or "",
            command=command,
            args=args if isinstance(args, list) else [args],
            env=env,
            transport=transport,
            url=url,
            config_path=config_path,
        )
        servers.append(server)

    return servers


def parse_snowflake_connections(config_path: str) -> list[MCPServer]:
    """Parse Snowflake CLI connections.toml or config.toml into inventory entries.

    Each connection profile becomes an MCPServer entry for inventory visibility.
    connections.toml uses [profile_name] sections; config.toml uses [connections.name].
    """
    try:
        data = toml.load(config_path)
    except Exception:  # noqa: BLE001 — toml libraries raise varied error types
        return []

    if not isinstance(data, dict):
        return []

    # connections.toml: top-level [profile_name] sections
    # config.toml: nested [connections.name] sections
    connections = data.get("connections", data)

    servers: list[MCPServer] = []
    for name, conn_def in connections.items():
        if not isinstance(conn_def, dict):
            continue
        if name in ("cli", "default_connection_name"):
            continue  # Skip non-connection sections

        account = conn_def.get("account", "")
        user = conn_def.get("user", "")

        # Build env dict with redacted credentials
        env: dict[str, str] = {}
        if account:
            env["account"] = account
        if user:
            env["user"] = user
        if conn_def.get("password"):
            env["password"] = "***REDACTED***"
        if conn_def.get("private_key_file"):
            env["private_key_file"] = "***KEY_FILE_PRESENT***"

        server = MCPServer(
            name=f"sf-connection:{name}",
            command=f"snow --connection {name}",
            args=[],
            env=env,
            transport=TransportType.UNKNOWN,
            config_path=config_path,
        )
        servers.append(server)

    return servers


# ---------------------------------------------------------------------------
# Cortex Code security audit
# ---------------------------------------------------------------------------


def parse_cortex_code_metadata(config_path: str) -> dict:
    """Parse Cortex Code auxiliary config files (permissions, hooks, settings).

    Returns metadata dict to attach to the agent for security audit visibility.
    """
    try:
        with open(config_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError, ValueError):
        return {}

    if not isinstance(data, dict):
        return {}

    filename = Path(config_path).name
    if filename == "permissions.json":
        return {"cortex_permissions": data, "cortex_permission_findings": audit_cortex_permissions(data)}
    elif filename == "hooks.json":
        return {"cortex_hooks": data, "cortex_hook_findings": audit_cortex_hooks(data)}
    elif filename == "settings.json" and "mcpServers" not in data:
        return {"cortex_settings": data}

    return {}


def audit_cortex_permissions(permissions: dict) -> list[dict]:
    """Audit Cortex Code permission cache for security risks.

    Flags:
    - PERSIST_ALLOW_ALL: "Always allow" entries (persist=true) bypass future prompts
    - HIGH_RISK_TOOL_APPROVED: Cached approval for dangerous tool capabilities
    - UNVERIFIED_SERVER_APPROVED: Server approved without integrity hash
    """
    findings: list[dict] = []
    high_risk_tools = {"execute", "shell", "run", "eval", "write", "delete", "rm", "sudo"}

    approvals = permissions.get("approvals", permissions.get("tools", []))
    if isinstance(approvals, dict):
        approvals = list(approvals.values())
    if not isinstance(approvals, list):
        return findings

    for entry in approvals:
        if not isinstance(entry, dict):
            continue
        tool_name = str(entry.get("tool", entry.get("name", "unknown")) or "unknown").lower()
        persist = entry.get("persist", entry.get("always_allow", False))
        server = entry.get("server", entry.get("mcp_server", ""))

        if persist:
            findings.append(
                {
                    "severity": "MEDIUM",
                    "type": "PERSIST_ALLOW_ALL",
                    "description": f"Tool '{tool_name}' has persistent 'always allow' — bypasses future approval prompts",
                    "tool": tool_name,
                    "server": server,
                }
            )

        if any(kw in tool_name for kw in high_risk_tools):
            findings.append(
                {
                    "severity": "HIGH",
                    "type": "HIGH_RISK_TOOL_APPROVED",
                    "description": f"High-risk tool '{tool_name}' has cached approval — could be exploited if server is compromised",
                    "tool": tool_name,
                    "server": server,
                }
            )

        if not entry.get("hash", entry.get("integrity", "")):
            findings.append(
                {
                    "severity": "LOW",
                    "type": "UNVERIFIED_SERVER_APPROVED",
                    "description": f"Tool '{tool_name}' approved without integrity verification (no hash) — rug pull risk",
                    "tool": tool_name,
                    "server": server,
                }
            )

    return findings


# Patterns that indicate dangerous hook commands
_DANGEROUS_HOOK_PATTERNS = re.compile(
    r"(curl\s.*\|\s*(?:ba)?sh|wget\s.*\|\s*(?:ba)?sh|exec\s|eval\s|"
    r"python\s+-c|node\s+-e|rm\s+-rf|chmod\s+777|>\s*/dev/|"
    r"sudo\s|doas\s|pkexec\s|chown\s+root|setuid|nsenter\s)",
    re.IGNORECASE,
)


def audit_claude_desktop_settings(config_data: dict, config_path: str) -> list[dict]:
    """Extract and flag risky Claude Desktop automation settings."""
    findings = []
    risky_settings = {
        "scheduledTasksEnabled": ("Autonomous scheduled task execution", "high"),
        "ccdScheduledTasksEnabled": ("Code Desktop scheduled tasks", "high"),
        "keepAwakeEnabled": ("Keep-awake prevents idle timeout", "medium"),
        "webSearchEnabled": ("Autonomous internet access", "high"),
    }
    for key, (desc, risk) in risky_settings.items():
        val = config_data.get(key)
        if val is True:
            findings.append(
                {
                    "setting": key,
                    "value": val,
                    "description": desc,
                    "risk_level": risk,
                    "config_path": config_path,
                }
            )
    return findings


def audit_cortex_hooks(hooks: dict) -> list[dict]:
    """Audit Cortex Code hook configuration for security risks.

    Flags:
    - DANGEROUS_HOOK_COMMAND: Hook runs shell command with known-dangerous patterns
    - UNRESTRICTED_HOOK_TRIGGER: Hook fires on all events (no event filter)
    - EXTERNAL_HOOK_URL: Hook sends data to external URL
    """
    findings: list[dict] = []

    hook_list = hooks.get("hooks", [])
    if isinstance(hook_list, dict):
        hook_list = list(hook_list.values())
    if not isinstance(hook_list, list):
        return findings

    for hook in hook_list:
        if not isinstance(hook, dict):
            continue
        hook_name = hook.get("name", hook.get("id", "unnamed"))
        command = hook.get("command", hook.get("script", ""))
        events = hook.get("events", hook.get("on", []))
        url = hook.get("url", hook.get("webhook", ""))

        if command and _DANGEROUS_HOOK_PATTERNS.search(command):
            findings.append(
                {
                    "severity": "HIGH",
                    "type": "DANGEROUS_HOOK_COMMAND",
                    "description": f"Hook '{hook_name}' runs dangerous command pattern: {command[:100]}",
                    "hook": hook_name,
                }
            )

        if not events or events == "*" or events == ["*"]:
            findings.append(
                {
                    "severity": "MEDIUM",
                    "type": "UNRESTRICTED_HOOK_TRIGGER",
                    "description": f"Hook '{hook_name}' fires on all events — should be scoped to specific triggers",
                    "hook": hook_name,
                }
            )

        if url and ("http://" in url or "https://" in url):
            findings.append(
                {
                    "severity": "MEDIUM",
                    "type": "EXTERNAL_HOOK_URL",
                    "description": f"Hook '{hook_name}' sends data to external URL: {url[:100]}",
                    "hook": hook_name,
                    "url": url[:200],
                }
            )

    return findings


# Custom parsers for non-JSON config formats
_CUSTOM_PARSERS: dict[Optional[str], str] = {
    # AgentType values mapped to format — imported as AgentType keys in __init__.py
}


def _parse_docker_mcp_catalog(
    enabled_names: set[str],
    catalog_path: Path,
) -> list[MCPServer]:
    """Parse Docker MCP catalog YAML and return MCPServer objects for enabled servers.

    The catalog at ``~/.docker/mcp/catalogs/docker-mcp.yaml`` contains 300+
    server definitions with image refs, tool lists, secrets, and metadata.
    We only parse entries that the user has enabled in ``registry.yaml``.
    """
    from agent_bom.floating_refs import classify_image_reference
    from agent_bom.models import MCPTool, Package

    try:
        catalog_data = yaml.safe_load(catalog_path.read_text())
    except (OSError, ValueError):
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
                tools.append(
                    MCPTool(
                        name=tool_entry["name"],
                        description=tool_entry.get("description", ""),
                    )
                )

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
        floating = classify_image_reference(image_ref)
        packages = [
            Package(
                name=pkg_name,
                version=pkg_version,
                ecosystem="docker",
                is_direct=True,
                floating_reference=floating is not None,
                floating_reference_reason=floating.reason if floating else None,
            )
        ]

        server = MCPServer(
            name=name,
            command=f"docker run {image_ref}",
            args=[],
            env=cred_env,
            transport=TransportType.STDIO,
            tools=tools,
            packages=packages,
            config_path=str(catalog_path),
            security_warnings=[floating.to_security_warning()] if floating else [],
        )
        servers.append(server)

    return servers
