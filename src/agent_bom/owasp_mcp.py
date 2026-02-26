"""OWASP Top 10 for Model Context Protocol (MCP) — tag blast radius findings.

Maps agent-bom findings to the OWASP Top 10 for MCP (2025 edition).
Every finding gets at minimum MCP04 (Software Supply Chain Attacks) since
any package CVE in an MCP server's dependency tree is by definition a
supply chain attack surface.

Reference: https://owasp.org/www-project-mcp-top-10/
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.models import Severity
from agent_bom.risk_analyzer import ToolCapability, classify_tool

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius


# ─── Catalog ──────────────────────────────────────────────────────────────────

OWASP_MCP_TOP10: dict[str, str] = {
    "MCP01": "Token Mismanagement & Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Software Supply Chain Attacks",
    "MCP05": "Command Injection & Execution",
    "MCP06": "Intent Flow Subversion",
    "MCP07": "Insufficient Authentication & Authorization",
    "MCP08": "Lack of Audit & Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection & Over-Sharing",
}

# Severity levels considered high-risk for privilege/poisoning checks
_HIGH_RISK_SEVERITIES: frozenset[Severity] = frozenset({
    Severity.CRITICAL,
    Severity.HIGH,
})


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted OWASP MCP Top 10 codes applicable to this blast radius.

    Rules applied:
    - MCP04: Always — any package CVE in an MCP server is a supply chain attack.
    - MCP01: Credential env vars exposed alongside a vulnerable package.
    - MCP02: Server has elevated privileges AND severity is CRITICAL/HIGH.
    - MCP03: Server is unverified in registry AND has HIGH+ CVE (poisoning risk).
    - MCP05: A reachable tool has EXECUTE capability.
    - MCP07: Server is unverified AND uses no-auth transport (stdio).
    - MCP09: Server found via discovery but not in the curated registry.
    - MCP10: A reachable tool has READ capability AND credentials are exposed.
    """
    tags: set[str] = {"MCP04"}  # always — supply chain attack surface

    # MCP01 — token/secret exposure via credential env vars
    if br.exposed_credentials:
        tags.add("MCP01")

    # MCP02 — privilege escalation via scope creep
    has_elevated = False
    for server in br.affected_servers:
        pp = server.permission_profile
        if pp and pp.is_elevated:
            has_elevated = True
            break
    if has_elevated and br.vulnerability.severity in _HIGH_RISK_SEVERITIES:
        tags.add("MCP02")

    # Many tools + high severity = scope creep even without explicit elevation
    if (
        len(br.exposed_tools) > 5
        and br.vulnerability.severity in _HIGH_RISK_SEVERITIES
    ):
        tags.add("MCP02")

    # MCP03 — tool poisoning: unverified server with high-severity CVE
    has_unverified = any(
        not s.registry_verified for s in br.affected_servers
    )
    if has_unverified and br.vulnerability.severity in _HIGH_RISK_SEVERITIES:
        tags.add("MCP03")

    # MCP03 — also triggered by known malicious packages (definitive poisoning)
    if br.package.is_malicious:
        tags.add("MCP03")

    # MCP05 / MCP10 — tool-level risks via semantic capability analysis
    has_read = False
    has_execute = False
    for tool in br.exposed_tools:
        caps = classify_tool(tool.name, tool.description)
        if ToolCapability.EXECUTE in caps:
            has_execute = True
        if ToolCapability.READ in caps:
            has_read = True

    if has_execute:
        tags.add("MCP05")

    # MCP10 — context injection/over-sharing: READ tools + credentials exposed
    if has_read and br.exposed_credentials:
        tags.add("MCP10")

    # MCP07 — insufficient auth: unverified server with stdio (no auth layer)
    from agent_bom.models import TransportType
    has_no_auth = any(
        not s.registry_verified and s.transport == TransportType.STDIO
        for s in br.affected_servers
    )
    if has_no_auth:
        tags.add("MCP07")

    # MCP09 — shadow MCP servers: discovered but not in curated registry
    if has_unverified:
        tags.add("MCP09")

    return sorted(tags)


def owasp_mcp_label(code: str) -> str:
    """Return human-readable label for an OWASP MCP code, e.g. 'MCP04 Supply Chain'."""
    name = OWASP_MCP_TOP10.get(code, "Unknown")
    return f"{code} {name}"


def owasp_mcp_labels(codes: list[str]) -> list[str]:
    """Return human-readable labels for a list of OWASP MCP codes."""
    return [owasp_mcp_label(c) for c in codes]
