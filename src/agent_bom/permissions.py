"""Tool permission classification and PermissionProfile construction.

Centralizes keyword-based classification of MCP tool permissions, risk level
inference, and PermissionProfile building. Used by:
- discovery/__init__.py (sudo/shell detection at discovery time)
- parsers/__init__.py (tool_permissions from registry data)
- scripts/expand_registry.py (auto-enrich new registry entries)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.models import PermissionProfile

# ── Keyword sets for tool classification ─────────────────────────────────────

_DESTRUCTIVE_KEYWORDS = frozenset({
    "delete", "remove", "drop", "destroy", "purge", "truncate", "wipe", "erase",
    "uninstall", "terminate", "kill",
})

_EXECUTE_KEYWORDS = frozenset({
    "exec", "execute", "run", "shell", "eval", "command", "invoke", "spawn",
    "call", "launch", "start_process",
})

_WRITE_KEYWORDS = frozenset({
    "write", "create", "update", "modify", "set", "put", "push", "post",
    "insert", "upload", "move", "rename", "copy", "send", "publish", "deploy",
    "scale", "restart", "apply", "patch", "merge", "commit",
})

_READ_KEYWORDS = frozenset({
    "read", "get", "list", "search", "query", "fetch", "find", "describe",
    "show", "download", "view", "inspect", "check", "count", "browse",
    "lookup", "resolve", "ping",
})

_SHELL_COMMANDS = frozenset({"sh", "bash", "zsh", "cmd", "powershell", "pwsh"})


# ── Public API ───────────────────────────────────────────────────────────────


def classify_tool(tool_name: str, tool_description: str = "") -> str:
    """Classify a tool's permission level from its name and description.

    Returns one of: ``"read"``, ``"write"``, ``"execute"``, ``"destructive"``.
    """
    combined = f"{tool_name} {tool_description}".lower()

    if any(kw in combined for kw in _DESTRUCTIVE_KEYWORDS):
        return "destructive"
    if any(kw in combined for kw in _EXECUTE_KEYWORDS):
        return "execute"
    if any(kw in combined for kw in _WRITE_KEYWORDS):
        return "write"
    return "read"


def classify_risk_level(tools: list[str], credential_env_vars: list[str]) -> str:
    """Classify risk_level for a registry entry based on tools and credentials.

    Returns ``"high"``, ``"medium"``, or ``"low"``.
    """
    has_creds = bool(credential_env_vars)
    tool_text = " ".join(tools).lower()

    has_dangerous = any(kw in tool_text for kw in _DESTRUCTIVE_KEYWORDS | _EXECUTE_KEYWORDS)
    has_write = any(kw in tool_text for kw in _WRITE_KEYWORDS)

    if (has_dangerous or has_write) and has_creds:
        return "high"
    if has_write or has_creds or has_dangerous:
        return "medium"
    return "low"


def build_tool_permissions(tools: list) -> dict[str, str]:
    """Build tool_permissions dict from a list of tool names or MCPTool objects."""
    result: dict[str, str] = {}
    for tool in tools:
        name = tool.name if hasattr(tool, "name") else str(tool)
        desc = tool.description if hasattr(tool, "description") else ""
        result[name] = classify_tool(name, desc)
    return result


def build_permission_profile(
    tools: list | None = None,
    credential_env_vars: list[str] | None = None,
    command: str = "",
    args: list[str] | None = None,
) -> "PermissionProfile":
    """Construct a PermissionProfile from tool list and command info."""
    from agent_bom.models import PermissionProfile

    tool_perms = build_tool_permissions(tools or [])

    has_write = any(v in ("write", "destructive") for v in tool_perms.values())
    has_exec = any(v == "execute" for v in tool_perms.values())
    has_shell = has_exec or command_is_shell(command, args or [])

    return PermissionProfile(
        tool_permissions=tool_perms,
        filesystem_write=has_write,
        shell_access=has_shell,
        network_access=bool(credential_env_vars),
        runs_as_root=command_runs_as_root(command, args or []),
    )


def _infer_category(qualified_name: str, description: str) -> str:
    """Infer registry category from server name and description."""
    combined = f"{qualified_name} {description}".lower()

    _category_keywords: dict[str, list[str]] = {
        "filesystem": ["filesystem", "file", "directory", "disk", "storage"],
        "database": ["database", "sql", "postgres", "mysql", "mongo", "redis", "sqlite", "supabase", "clickhouse"],
        "developer-tools": ["github", "gitlab", "git", "code", "ide", "dev", "build", "npm", "docker"],
        "cloud": ["aws", "gcp", "azure", "cloud", "s3", "lambda", "kubernetes", "k8s"],
        "ai-ml": ["openai", "anthropic", "llm", "ai", "ml", "model", "embedding", "ollama", "huggingface"],
        "communication": ["slack", "email", "discord", "teams", "notification", "twilio"],
        "web": ["browser", "http", "fetch", "web", "scrape", "puppeteer", "playwright"],
        "security": ["security", "vault", "secret", "encrypt", "auth", "sso"],
        "monitoring": ["monitor", "log", "metric", "alert", "grafana", "datadog", "sentry"],
        "data": ["data", "etl", "csv", "json", "transform", "analytics"],
    }

    for category, keywords in _category_keywords.items():
        if any(kw in combined for kw in keywords):
            return category
    return "general"


def command_runs_as_root(command: str, args: list[str]) -> bool:
    """Check if command uses sudo or runs explicitly as root."""
    if command == "sudo":
        return True
    if "sudo" in args:
        return True
    return False


def command_is_shell(command: str, args: list[str]) -> bool:
    """Check if command is a shell interpreter."""
    cmd_base = command.rsplit("/", 1)[-1] if "/" in command else command
    return cmd_base in _SHELL_COMMANDS or any(
        a.rsplit("/", 1)[-1] in _SHELL_COMMANDS for a in args
    )
