"""OWASP Top 10 for Agentic Applications (2026) — tag blast radius findings.

Maps agent-bom findings to the OWASP Top 10 for Agentic Applications,
released December 2025 with 100+ contributors.  Covers autonomous AI
agent-specific risks including supply chain attacks through MCP servers,
tool misuse, identity abuse, and cascading failures.

Reference: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.constants import AI_PACKAGES as _AI_PACKAGES
from agent_bom.constants import high_risk_severities
from agent_bom.risk_analyzer import ToolCapability, classify_mcp_tool

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius


# ─── Catalog ──────────────────────────────────────────────────────────────────

OWASP_AGENTIC_TOP10: dict[str, str] = {
    "ASI01": "Excessive Agency & Autonomy",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Hallucination Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agent Persistence",
}

_HIGH_RISK = high_risk_severities()


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted OWASP Agentic Top 10 codes applicable to this blast radius.

    Rules:
    - ASI01: Always — any agent CVE implies autonomy risk.
    - ASI02: Exposed tools + HIGH+ severity (tool misuse via exploit).
    - ASI03: Credentials exposed + elevated permissions.
    - ASI04: Always — supply chain is core domain.
    - ASI05: EXECUTE-capable tools reachable.
    - ASI06: READ-capable tools + AI framework package.
    - ASI07: >1 affected agent (cross-agent blast radius).
    - ASI08: AI framework + HIGH+ severity + >3 tools (cascading risk).
    - ASI09: Always — any vuln in agent stack = trust exploitation risk.
    - ASI10: Credentials + EXECUTE capability + HIGH+ (persistent rogue).
    """
    # Agentic tags only apply when there are actual agents in the blast radius.
    # A container image scan with no agent context should NOT get Agentic tags.
    if not br.affected_agents:
        return []

    tags: set[str] = {
        "ASI01",  # autonomy risk (within agentic context)
        "ASI04",  # supply chain (within agentic context)
        "ASI09",  # trust exploitation (within agentic context)
    }

    has_exec = False
    has_read = False
    for tool in br.exposed_tools:
        caps = classify_mcp_tool(tool)
        if ToolCapability.EXECUTE in caps:
            has_exec = True
        if ToolCapability.READ in caps:
            has_read = True

    is_high = br.vulnerability.severity in _HIGH_RISK
    is_ai_pkg = br.package.name.lower() in _AI_PACKAGES

    # ASI02 — tool misuse: tools reachable + high severity
    if br.exposed_tools and is_high:
        tags.add("ASI02")

    # ASI03 — identity & privilege abuse: credentials + elevated
    if br.exposed_credentials:
        tags.add("ASI03")
        # Elevated permissions amplify the risk
        for srv in br.affected_servers:
            if srv.permission_profile and srv.permission_profile.is_elevated:
                break

    # ASI05 — unexpected code execution
    if has_exec:
        tags.add("ASI05")

    # ASI06 — memory & context poisoning: read tools + AI framework
    if has_read and is_ai_pkg:
        tags.add("ASI06")

    # ASI07 — insecure inter-agent communication: multi-agent blast
    if len(br.affected_agents) > 1:
        tags.add("ASI07")

    # ASI08 — cascading failures: AI framework + high + broad tool surface
    if is_ai_pkg and is_high and len(br.exposed_tools) > 3:
        tags.add("ASI08")

    # ASI10 — rogue agent persistence: creds + exec + high severity
    if br.exposed_credentials and has_exec and is_high:
        tags.add("ASI10")

    return sorted(tags)


def owasp_agentic_label(code: str) -> str:
    """Return human-readable label, e.g. 'ASI04 Agentic Supply Chain Vulnerabilities'."""
    name = OWASP_AGENTIC_TOP10.get(code, "Unknown")
    return f"{code} {name}"


def owasp_agentic_labels(codes: list[str]) -> list[str]:
    """Return human-readable labels for a list of OWASP Agentic codes."""
    return [owasp_agentic_label(c) for c in codes]
