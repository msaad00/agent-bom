"""SOC 2 Trust Services Criteria — map findings to applicable criteria.

Maps agent-bom blast radius findings to the AICPA SOC 2 Trust Services
Criteria relevant to software supply chain security.  Every finding
triggers at minimum CC9.1 (risk mitigation) and CC9.2 (vendor risk).
CC7.1 (detection of new vulnerabilities and configuration changes) is a
detective criterion: the scan itself evidences it (see
``evidence.control_modes``), so findings are never tagged onto it.

Reference: https://www.aicpa.org/resources/landing/system-and-organization-controls-soc-suite-of-services
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.evidence.control_modes import finding_taggable_controls
from agent_bom.risk_analyzer import ToolCapability, classify_mcp_tool

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius


# ─── Catalog ──────────────────────────────────────────────────────────────────

# NOTE — the descriptors below are agent-bom's OWN short wording for each
# criterion area, not the official AICPA Trust Services Criteria text. The AICPA
# TSC is copyrighted, so its criteria text is NOT reproduced or redistributed
# here; only the criterion **identifier** (the fact) is used. Consult the AICPA
# source for the official wording:
# https://www.aicpa.org/resources/landing/system-and-organization-controls-soc-suite-of-services
SOC2_TSC: dict[str, str] = {
    # CC6 — Logical and physical access controls
    "CC6.1": "Logical/physical access restriction",
    "CC6.6": "External access-boundary protection",
    "CC6.8": "Unauthorized/malicious software prevention and detection",
    # CC7 — System operations
    "CC7.1": "Vulnerability and configuration-change detection",
    "CC7.2": "System-component anomaly monitoring",
    "CC7.4": "Security-incident response",
    # CC8 — Change management
    "CC8.1": "Change authorization and control",
    # CC9 — Risk mitigation
    "CC9.1": "Risk-mitigation activities",
    "CC9.2": "Vendor/third-party risk management",
}


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted SOC 2 TSC codes applicable to this blast radius.

    Rules:
    - CC9.1:  Always — risk mitigation needed for any CVE.
    - CC9.2:  Always — vendor/partner risk management (third-party package).
    - CC6.1:  Credentials exposed (access control concern).
    - CC6.6:  EXECUTE-capable tools (boundary enforcement needed).
    - CC6.8:  Package is known malicious (unauthorized/malicious software).
    - CC7.4:  KEV vulnerability (incident response needed).
    - CC8.1:  Fixable vulnerability (change management for remediation).

    CC7.1 is detective (evidenced by the scan) and CC7.2 needs runtime anomaly
    evidence a dependency finding does not carry; neither is tagged here.
    """
    tags: set[str] = {
        "CC9.1",  # always — risk mitigation
        "CC9.2",  # always — vendor risk management
    }

    has_exec = False
    for tool in br.exposed_tools:
        caps = classify_mcp_tool(tool)
        if ToolCapability.EXECUTE in caps:
            has_exec = True

    # CC6.1 — access controls: credentials exposed
    if br.exposed_credentials:
        tags.add("CC6.1")

    # CC6.6 — security boundaries: EXECUTE-capable tools
    if has_exec:
        tags.add("CC6.6")

    # CC6.8 — unauthorized/malicious software: known-malicious package
    if br.package.is_malicious:
        tags.add("CC6.8")

    # CC7.4 — incident response: KEV (active exploitation)
    if br.vulnerability.is_kev:
        tags.add("CC7.4")

    # CC8.1 — change management: fixable vulnerability
    if br.vulnerability.fixed_version:
        tags.add("CC8.1")

    # CWE-based compliance tagging (applies to all vulns with CWE data)
    if br.vulnerability.cwe_ids:
        from agent_bom.framework_mapping import controls_for_cwes

        tags.update(controls_for_cwes(br.vulnerability.cwe_ids, "soc2"))

    return sorted(finding_taggable_controls("soc2_tags", tags))


def soc2_label(code: str) -> str:
    """Return human-readable label, e.g. 'CC7.1 Vulnerability and configuration-change detection'."""
    name = SOC2_TSC.get(code, "Unknown")
    return f"{code} {name}"


def soc2_labels(codes: list[str]) -> list[str]:
    """Return human-readable labels for a list of SOC 2 TSC codes."""
    return [soc2_label(c) for c in codes]
