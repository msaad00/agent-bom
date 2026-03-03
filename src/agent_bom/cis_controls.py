"""CIS Controls v8 — map findings to applicable safeguards.

Maps agent-bom blast radius findings to the Center for Internet Security (CIS)
Controls v8 safeguards relevant to software supply chain security.  Every
finding triggers at minimum CIS-02 (Software Asset Inventory) and CIS-07
(Vulnerability Management) since any CVE requires both.

NOTE: These are the generic CIS Controls v8 (cross-platform).  CIS also
publishes platform-specific Benchmarks (e.g., CIS AWS Foundations, CIS GCP,
CIS Azure, CIS Snowflake) which apply additional host/cloud hardening checks.
Platform-specific CIS Benchmark mapping is planned for a future release.

Reference: https://www.cisecurity.org/controls/v8
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.constants import AI_PACKAGES as _AI_PACKAGES
from agent_bom.constants import high_risk_severities
from agent_bom.risk_analyzer import ToolCapability, classify_tool

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius

_HIGH_RISK = high_risk_severities()

# ─── Catalog ──────────────────────────────────────────────────────────────────

CIS_CONTROLS: dict[str, str] = {
    # CIS 02 — Inventory and Control of Software Assets
    "CIS-02.1": "Establish and maintain a software inventory",
    "CIS-02.3": "Address unauthorized software",
    "CIS-02.7": "Allowlist authorized libraries",
    # CIS 07 — Continuous Vulnerability Management
    "CIS-07.1": "Establish and maintain a vulnerability management process",
    "CIS-07.4": "Perform automated patch management",
    "CIS-07.5": "Perform automated vulnerability scans of internal assets",
    "CIS-07.6": "Perform automated vulnerability scans of public-facing assets",
    # CIS 16 — Application Software Security
    "CIS-16.1": "Establish and maintain a secure application development process",
    "CIS-16.11": "Use standard hardening configuration templates",
    "CIS-16.12": "Implement code-level security checks",
}


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted CIS Controls v8 safeguard IDs applicable to this blast radius.

    Rules:
    - CIS-02.1: Always — software inventory (package tracked in BOM).
    - CIS-07.1: Always — vulnerability management process.
    - CIS-07.5: Always — automated vulnerability scanning performed.
    - CIS-02.3: HIGH+ severity (unauthorized/risky software).
    - CIS-02.7: AI framework package (library allowlisting relevant).
    - CIS-07.4: Fixable vulnerability (patch management needed).
    - CIS-07.6: >1 affected agent (public-facing scan scope).
    - CIS-16.1: Credentials exposed (secure development process gap).
    - CIS-16.11: EXECUTE-capable tools (hardening needed).
    - CIS-16.12: KEV vulnerability (code-level security check urgency).
    """
    tags: set[str] = {
        "CIS-02.1",  # always — software inventory
        "CIS-07.1",  # always — vulnerability management
        "CIS-07.5",  # always — automated scanning
    }

    is_high = br.vulnerability.severity in _HIGH_RISK

    has_exec = False
    for tool in br.exposed_tools:
        caps = classify_tool(tool.name, tool.description)
        if ToolCapability.EXECUTE in caps:
            has_exec = True

    # CIS-02.3 — unauthorized software: HIGH+ severity
    if is_high:
        tags.add("CIS-02.3")

    # CIS-02.7 — library allowlisting: AI framework package
    if br.package.name.lower() in _AI_PACKAGES:
        tags.add("CIS-02.7")

    # CIS-07.4 — patch management: fixable vulnerability
    if br.vulnerability.fixed_version:
        tags.add("CIS-07.4")

    # CIS-07.6 — public-facing scans: multi-agent exposure
    if len(br.affected_agents) > 1:
        tags.add("CIS-07.6")

    # CIS-16.1 — secure development: credentials exposed
    if br.exposed_credentials:
        tags.add("CIS-16.1")

    # CIS-16.11 — hardening: EXECUTE-capable tools
    if has_exec:
        tags.add("CIS-16.11")

    # CIS-16.12 — code security: KEV (active exploitation)
    if br.vulnerability.is_kev:
        tags.add("CIS-16.12")

    return sorted(tags)


def cis_label(code: str) -> str:
    """Return human-readable label, e.g. 'CIS-07.1 Establish and maintain a vulnerability management process'."""
    name = CIS_CONTROLS.get(code, "Unknown")
    return f"{code} {name}"


def cis_labels(codes: list[str]) -> list[str]:
    """Return human-readable labels for a list of CIS Controls safeguard IDs."""
    return [cis_label(c) for c in codes]
