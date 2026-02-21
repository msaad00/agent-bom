"""Deep AI risk analysis — tool capability taxonomy and holistic server risk scoring.

Replaces shallow keyword matching with a semantic capability classification system.
Each MCP tool gets classified by capability type (READ, WRITE, DELETE, EXECUTE, etc.)
and servers receive a holistic risk score based on their tool portfolio and credential
exposure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from agent_bom.models import MCPTool


# ─── Capability Taxonomy ─────────────────────────────────────────────────────


class ToolCapability(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    NETWORK = "network"
    AUTH = "auth"
    ADMIN = "admin"


CAPABILITY_WEIGHTS: dict[ToolCapability, float] = {
    ToolCapability.READ: 1.0,
    ToolCapability.WRITE: 3.0,
    ToolCapability.DELETE: 4.0,
    ToolCapability.EXECUTE: 5.0,
    ToolCapability.NETWORK: 2.0,
    ToolCapability.AUTH: 4.0,
    ToolCapability.ADMIN: 5.0,
}

CAPABILITY_PATTERNS: dict[ToolCapability, list[str]] = {
    ToolCapability.READ: [
        "read", "get", "list", "search", "query", "describe",
        "show", "view", "find", "lookup", "inspect", "cat", "head",
        "select", "browse", "scan", "check", "status",
    ],
    ToolCapability.WRITE: [
        "write", "create", "add", "insert", "update", "set", "put",
        "post", "send", "upload", "push", "modify", "edit", "append",
        "save", "store", "move", "rename", "copy", "patch",
    ],
    ToolCapability.DELETE: [
        "delete", "remove", "drop", "destroy", "clear", "purge",
        "truncate", "revoke", "unlink", "rm", "wipe", "reset",
    ],
    ToolCapability.EXECUTE: [
        "exec", "execute", "run", "shell", "bash", "eval", "spawn",
        "invoke", "subprocess", "command", "script", "deploy",
        "popen", "terminal", "cmd",
    ],
    ToolCapability.NETWORK: [
        "fetch", "request", "http", "curl", "download", "scrape",
        "browse", "navigate", "connect", "webhook", "api_call",
        "socket", "tcp", "udp",
    ],
    ToolCapability.AUTH: [
        "login", "auth", "token", "credential", "password", "secret",
        "oauth", "session", "key", "certificate", "sign",
    ],
    ToolCapability.ADMIN: [
        "config", "permission", "role", "grant", "admin", "manage",
        "install", "migrate", "provision", "scale",
    ],
}

# Dangerous capability combinations and their risk descriptions
DANGEROUS_COMBOS: list[tuple[set[ToolCapability], str]] = [
    (
        {ToolCapability.EXECUTE, ToolCapability.WRITE},
        "Can write arbitrary files and execute commands — full system compromise possible",
    ),
    (
        {ToolCapability.EXECUTE},
        "Can execute arbitrary code/commands",
    ),
    (
        {ToolCapability.DELETE, ToolCapability.WRITE},
        "Can create and delete data — ransomware risk",
    ),
    (
        {ToolCapability.NETWORK, ToolCapability.READ},
        "Can read local data and exfiltrate over network",
    ),
    (
        {ToolCapability.AUTH, ToolCapability.NETWORK},
        "Can access credentials and make outbound requests — credential theft risk",
    ),
    (
        {ToolCapability.WRITE, ToolCapability.AUTH},
        "Can modify data and access credentials — privilege escalation risk",
    ),
    (
        {ToolCapability.DELETE},
        "Can destroy data or resources",
    ),
    (
        {ToolCapability.ADMIN},
        "Has administrative capabilities — configuration tampering risk",
    ),
]


# ─── Classification ──────────────────────────────────────────────────────────


def classify_tool(tool_name: str, description: str = "") -> list[ToolCapability]:
    """Classify a tool into capability categories based on name and description.

    Returns a deduplicated list of ToolCapability values.
    """
    combined = (tool_name + " " + description).lower()
    caps: set[ToolCapability] = set()

    for capability, patterns in CAPABILITY_PATTERNS.items():
        for pattern in patterns:
            if pattern in combined:
                caps.add(capability)
                break  # One match per capability is enough

    return sorted(caps, key=lambda c: c.value)


def has_capability(tools: list[MCPTool], capability: ToolCapability) -> bool:
    """Check if any tool in the list has the given capability."""
    return any(
        capability in classify_tool(t.name, t.description)
        for t in tools
    )


def get_capabilities(tools: list[MCPTool]) -> dict[ToolCapability, list[str]]:
    """Map each capability to the tool names that provide it."""
    result: dict[ToolCapability, list[str]] = {cap: [] for cap in ToolCapability}
    for tool in tools:
        for cap in classify_tool(tool.name, tool.description):
            result[cap].append(tool.name)
    return {cap: names for cap, names in result.items() if names}


# ─── Server Risk Scoring ─────────────────────────────────────────────────────


@dataclass
class ServerRiskProfile:
    """Holistic risk profile for an MCP server."""

    risk_score: float = 0.0
    risk_level: str = "low"
    capabilities: dict[str, int] = field(default_factory=dict)
    capability_tools: dict[str, list[str]] = field(default_factory=dict)
    dangerous_combinations: list[str] = field(default_factory=list)
    justification: str = ""
    tool_count: int = 0
    credential_count: int = 0


def score_server_risk(
    tools: list[MCPTool],
    credentials: list[str] | None = None,
    registry_entry: Optional[dict] = None,
) -> ServerRiskProfile:
    """Compute holistic risk profile for an MCP server.

    Factors:
    - Tool capability weights (EXECUTE=5, DELETE=4, WRITE=3, etc.)
    - Number of tools (more surface = more risk)
    - Credential exposure (amplifies tool risk)
    - Dangerous capability combinations
    - Registry-provided risk level (if available)
    """
    credentials = credentials or []
    profile = ServerRiskProfile(
        tool_count=len(tools),
        credential_count=len(credentials),
    )

    # Classify all tools
    cap_map = get_capabilities(tools)
    cap_counts: dict[str, int] = {}
    cap_tool_names: dict[str, list[str]] = {}
    present_caps: set[ToolCapability] = set()

    for cap, tool_names in cap_map.items():
        cap_counts[cap.value] = len(tool_names)
        cap_tool_names[cap.value] = tool_names
        present_caps.add(cap)

    profile.capabilities = cap_counts
    profile.capability_tools = cap_tool_names

    # Base score from capability weights
    weighted_score = 0.0
    for cap in present_caps:
        weighted_score += CAPABILITY_WEIGHTS.get(cap, 1.0)

    # Normalize: 0-10 scale based on max possible (all 7 caps)
    max_weight = sum(CAPABILITY_WEIGHTS.values())
    base_score = min((weighted_score / max_weight) * 7.0, 7.0)

    # Tool count factor: more tools = more surface area
    tool_factor = min(len(tools) * 0.15, 1.5)

    # Credential amplification
    cred_factor = min(len(credentials) * 0.5, 2.0)

    # Dangerous combinations
    combos_found: list[str] = []
    for required_caps, description in DANGEROUS_COMBOS:
        # Check if server has all caps in the combo
        if required_caps.issubset(present_caps):
            combos_found.append(description)

    combo_factor = min(len(combos_found) * 0.3, 1.5)
    profile.dangerous_combinations = combos_found

    # Registry override: if registry says high, minimum floor
    registry_floor = 0.0
    if registry_entry:
        rl = registry_entry.get("risk_level", "")
        if rl == "high":
            registry_floor = 6.0
        elif rl == "medium":
            registry_floor = 3.0

    raw_score = base_score + tool_factor + cred_factor + combo_factor
    profile.risk_score = min(max(raw_score, registry_floor), 10.0)

    # Risk level
    if profile.risk_score >= 7.0:
        profile.risk_level = "critical" if profile.risk_score >= 9.0 else "high"
    elif profile.risk_score >= 4.0:
        profile.risk_level = "medium"
    else:
        profile.risk_level = "low"

    # Generate justification
    profile.justification = _generate_justification(profile, present_caps, credentials)

    return profile


def _generate_justification(
    profile: ServerRiskProfile,
    present_caps: set[ToolCapability],
    credentials: list[str],
) -> str:
    """Generate a human-readable risk justification."""
    parts: list[str] = []

    # Capability summary
    cap_names = sorted(c.value.upper() for c in present_caps)
    if cap_names:
        parts.append(f"Server has {', '.join(cap_names)} capabilities across {profile.tool_count} tool(s).")

    # Dangerous combos
    if profile.dangerous_combinations:
        parts.append(f"Dangerous combinations detected: {profile.dangerous_combinations[0]}.")

    # Credentials
    if credentials:
        parts.append(f"{len(credentials)} credential(s) exposed ({', '.join(credentials[:3])}).")

    # Specific high-risk tools
    high_risk_caps = {ToolCapability.EXECUTE, ToolCapability.DELETE, ToolCapability.ADMIN}
    for cap in high_risk_caps:
        tool_names = profile.capability_tools.get(cap.value, [])
        if tool_names:
            parts.append(
                f"{cap.value.upper()} tools: {', '.join(tool_names[:3])}"
                + (f" (+{len(tool_names) - 3} more)" if len(tool_names) > 3 else "")
                + "."
            )

    return " ".join(parts) if parts else "Minimal capability surface."
