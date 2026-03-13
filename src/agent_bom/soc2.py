"""SOC 2 Trust Services Criteria — map findings to applicable criteria.

Maps agent-bom blast radius findings to the AICPA SOC 2 Trust Services
Criteria relevant to software supply chain security.  Every finding
triggers at minimum CC7.1 (anomaly detection) and CC9.1 (risk mitigation)
since any CVE in an AI agent dependency tree requires both.

Reference: https://www.aicpa.org/resources/landing/system-and-organization-controls-soc-suite-of-services
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

SOC2_TSC: dict[str, str] = {
    # CC6 — Logical and physical access controls
    "CC6.1": "Logical and physical access controls implemented",
    "CC6.6": "Security boundaries and system access restricted",
    "CC6.8": "Unauthorized or malicious software prevented or detected",
    # CC7 — System operations
    "CC7.1": "Detection and monitoring of anomalies and events",
    "CC7.2": "Monitoring of system components for anomalies",
    "CC7.4": "Incident response activities executed",
    # CC8 — Change management
    "CC8.1": "Change management processes authorized and implemented",
    # CC9 — Risk mitigation
    "CC9.1": "Risk mitigation activities identified and applied",
    "CC9.2": "Vendor and business partner risk is managed",
}


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted SOC 2 TSC codes applicable to this blast radius.

    Rules:
    - CC7.1:  Always — anomaly detection triggered by vulnerability.
    - CC9.1:  Always — risk mitigation needed for any CVE.
    - CC9.2:  Always — vendor/partner risk management (third-party package).
    - CC6.1:  Credentials exposed (access control concern).
    - CC6.6:  EXECUTE-capable tools (boundary enforcement needed).
    - CC6.8:  HIGH+ severity (malicious software risk).
    - CC7.2:  AI framework package (system component monitoring).
    - CC7.4:  KEV vulnerability (incident response needed).
    - CC8.1:  Fixable vulnerability (change management for remediation).
    """
    tags: set[str] = {
        "CC7.1",  # always — anomaly detection
        "CC9.1",  # always — risk mitigation
        "CC9.2",  # always — vendor risk management
    }

    is_high = br.vulnerability.severity in _HIGH_RISK

    has_exec = False
    for tool in br.exposed_tools:
        caps = classify_tool(tool.name, tool.description)
        if ToolCapability.EXECUTE in caps:
            has_exec = True

    # CC6.1 — access controls: credentials exposed
    if br.exposed_credentials:
        tags.add("CC6.1")

    # CC6.6 — security boundaries: EXECUTE-capable tools
    if has_exec:
        tags.add("CC6.6")

    # CC6.8 — malicious software: HIGH+ severity
    if is_high:
        tags.add("CC6.8")

    # CC7.2 — component monitoring: AI framework package
    if br.package.name.lower() in _AI_PACKAGES:
        tags.add("CC7.2")

    # CC7.4 — incident response: KEV (active exploitation)
    if br.vulnerability.is_kev:
        tags.add("CC7.4")

    # CC8.1 — change management: fixable vulnerability
    if br.vulnerability.fixed_version:
        tags.add("CC8.1")

    # CWE-based compliance tagging (applies to all vulns with CWE data)
    if br.vulnerability.cwe_ids:
        from agent_bom.constants import CWE_COMPLIANCE_MAP

        for cwe in br.vulnerability.cwe_ids:
            for tag in CWE_COMPLIANCE_MAP.get(cwe.upper(), {}).get("soc2", []):
                tags.add(tag)

    return sorted(tags)


def soc2_label(code: str) -> str:
    """Return human-readable label, e.g. 'CC7.1 Detection and monitoring of anomalies and events'."""
    name = SOC2_TSC.get(code, "Unknown")
    return f"{code} {name}"


def soc2_labels(codes: list[str]) -> list[str]:
    """Return human-readable labels for a list of SOC 2 TSC codes."""
    return [soc2_label(c) for c in codes]
