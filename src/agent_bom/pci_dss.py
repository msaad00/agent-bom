"""PCI DSS 4.0 compliance — map findings to applicable requirements.

Maps agent-bom blast radius findings to PCI DSS 4.0 requirements
relevant to software supply chain security and vulnerability management.

Key requirements covered:
- Req 6.2.4: Software engineering security practices
- Req 6.3.1: Identify vulnerabilities using reputable sources
- Req 6.3.2: Inventory of custom/third-party software components (SBOM)
- Req 6.3.3: Patch/update critical/high vulnerabilities timely
- Req 11.3.1: Internal vulnerability scans quarterly
- Req 11.3.2: External ASV scans quarterly
- Req 12.3.1: Risk assessment for critical assets

Reference: https://www.pcisecuritystandards.org/document_library/
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.constants import AI_PACKAGES as _AI_PACKAGES
from agent_bom.constants import high_risk_severities
from agent_bom.risk_analyzer import ToolCapability, classify_mcp_tool

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius

_HIGH_RISK = high_risk_severities()

# ─── Catalog ──────────────────────────────────────────────────────────────────

# NOTE — the descriptors below are agent-bom's OWN short wording for each PCI DSS
# requirement area, not the official PCI DSS 4.0 requirement text. PCI DSS is
# copyrighted by the PCI Security Standards Council, so its requirement wording is
# NOT reproduced or redistributed here; only the requirement **identifier** (the
# fact) is used. Consult the standard for the official text:
# https://www.pcisecuritystandards.org/document_library/
PCI_DSS_REQUIREMENTS: dict[str, str] = {
    # Requirement 6 — Develop and maintain secure systems and software
    "6.2.4": "Secure software-engineering practices",
    "6.3.1": "Vulnerability identification from reputable sources",
    "6.3.2": "Third-party / custom software component inventory",
    "6.3.3": "Timely security patching",
    # Requirement 11 — Regularly test security systems and networks
    "11.3.1": "Internal vulnerability scanning",
    "11.3.2": "External / ASV vulnerability scanning",
    # Requirement 12 — Maintain policy that addresses information security
    "12.3.1": "Critical-asset risk assessment",
    "12.3.4": "Periodic cryptographic-suite review",
    # Requirement 2 — Apply secure configurations
    "2.2.1": "Secure configuration standards",
    "2.2.7": "Encrypted administrative access",
    # Requirement 8 — Identify users and authenticate access
    "8.3.6": "Authentication-factor strength",
    "8.6.1": "Least-privilege system accounts",
}


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted PCI DSS 4.0 requirement IDs applicable to this blast radius.

    Rules:
    - 6.3.1:  Always — vulnerability identified from reputable source (OSV/NVD).
    - 6.3.2:  Always — third-party component in inventory (SBOM).
    - 11.3.1: Always — vulnerability scan finding.
    - 6.3.3:  HIGH+ severity or fixable — patching urgency.
    - 6.2.4:  Exposed tools with EXECUTE capability — secure engineering.
    - 12.3.1: Credential exposure — critical asset risk assessment.
    - 8.6.1:  Credential exposure — least privilege access.
    - 2.2.1:  Configuration vulnerability (MCP server misconfiguration).
    - 11.3.2: KEV vulnerability — requires external validation.
    - 12.3.4: Cryptographic vulnerability (CWE-based).
    """
    tags: set[str] = {
        "6.3.1",  # always — vuln from reputable source
        "6.3.2",  # always — third-party component inventory
        "11.3.1",  # always — internal scan finding
    }

    is_high = br.vulnerability.severity in _HIGH_RISK

    has_exec = False
    for tool in br.exposed_tools:
        caps = classify_mcp_tool(tool)
        if ToolCapability.EXECUTE in caps:
            has_exec = True

    # 6.3.3 — Patch critical/high vulns timely
    if is_high or br.vulnerability.fixed_version:
        tags.add("6.3.3")

    # 6.2.4 — Secure engineering: EXECUTE-capable tools exposed
    if has_exec:
        tags.add("6.2.4")

    # 12.3.1 — Risk assessment: credentials exposed (critical asset)
    if br.exposed_credentials:
        tags.add("12.3.1")

    # 8.6.1 — Least privilege: credentials exposed
    if br.exposed_credentials:
        tags.add("8.6.1")

    # 2.2.1 — Secure configuration: AI framework package
    if br.package.name.lower() in _AI_PACKAGES:
        tags.add("2.2.1")

    # 11.3.2 — External validation: KEV (active exploitation)
    if br.vulnerability.is_kev:
        tags.add("11.3.2")

    # CWE-based: crypto weaknesses → 12.3.4
    crypto_cwes = {"CWE-327", "CWE-328", "CWE-326", "CWE-295", "CWE-310"}
    if br.vulnerability.cwe_ids and any(c.upper() in crypto_cwes for c in br.vulnerability.cwe_ids):
        tags.add("12.3.4")

    # CWE-based compliance tagging
    if br.vulnerability.cwe_ids:
        from agent_bom.framework_mapping import controls_for_cwes

        tags.update(controls_for_cwes(br.vulnerability.cwe_ids, "pci_dss"))

    return sorted(tags)


def pci_dss_label(code: str) -> str:
    """Return human-readable label, e.g. '6.3.1 Security vulnerabilities identified...'."""
    name = PCI_DSS_REQUIREMENTS.get(code, "Unknown")
    return f"PCI-DSS {code}: {name}"


def pci_dss_labels(codes: list[str]) -> list[str]:
    """Return human-readable labels for a list of PCI DSS requirement codes."""
    return [pci_dss_label(c) for c in codes]
