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

PCI_DSS_REQUIREMENTS: dict[str, str] = {
    # Requirement 6 — Develop and maintain secure systems and software
    "6.2.4": "Software engineering practices prevent and mitigate common software attacks and vulnerabilities",
    "6.3.1": "Security vulnerabilities identified and managed using reputable external sources",
    "6.3.2": "Inventory of bespoke and custom software, and third-party software components maintained",
    "6.3.3": "Security patches/updates installed to protect against known vulnerabilities",
    # Requirement 11 — Regularly test security systems and networks
    "11.3.1": "Internal vulnerability scans performed at least quarterly",
    "11.3.2": "External vulnerability scans performed at least quarterly by PCI SSC ASV",
    # Requirement 12 — Maintain policy that addresses information security
    "12.3.1": "Risk assessment performed for each entity's critical assets, threats, and vulnerabilities",
    "12.3.4": "Cryptographic cipher suites and protocols in use reviewed annually",
    # Requirement 2 — Apply secure configurations
    "2.2.1": "System configuration standards address all known security vulnerabilities",
    "2.2.7": "All non-console administrative access encrypted with strong cryptography",
    # Requirement 8 — Identify users and authenticate access
    "8.3.6": "Passwords/passphrases meet minimum complexity requirements",
    "8.6.1": "System or application accounts managed based on least privilege",
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
        from agent_bom.constants import CWE_COMPLIANCE_MAP

        for cwe in br.vulnerability.cwe_ids:
            for tag in CWE_COMPLIANCE_MAP.get(cwe.upper(), {}).get("pci_dss", []):
                tags.add(tag)

    return sorted(tags)


def pci_dss_label(code: str) -> str:
    """Return human-readable label, e.g. '6.3.1 Security vulnerabilities identified...'."""
    name = PCI_DSS_REQUIREMENTS.get(code, "Unknown")
    return f"PCI-DSS {code}: {name}"


def pci_dss_labels(codes: list[str]) -> list[str]:
    """Return human-readable labels for a list of PCI DSS requirement codes."""
    return [pci_dss_label(c) for c in codes]
