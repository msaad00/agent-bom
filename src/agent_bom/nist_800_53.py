"""NIST 800-53 Rev 5 — map findings to security and privacy controls.

Maps agent-bom blast radius findings to NIST SP 800-53 Rev 5 controls
relevant to vulnerability management, supply chain security, and AI
infrastructure protection.  Every finding triggers at minimum SI-2 (flaw
remediation) and SR-3 (supply chain controls) since any package CVE in an AI
agent dependency tree is an unremediated flaw reaching the estate through the
supply chain.

Only CORRECTIVE / PREVENTIVE controls are tagged here — controls an open
finding is evidence AGAINST. Two other classes are deliberately excluded (see
:mod:`agent_bom.evidence.control_modes`):

* **Detective** controls — RA-5 "Monitor and scan for vulnerabilities in the
  system and hosted applications" and CM-8 "Develop and document an inventory
  of system components" — are IMPLEMENTED BY this scan. Producing this scan and
  this SBOM is evidence they operate, so tagging a finding onto them (and
  therefore failing them) inverts the evidence. They are scored from scan
  freshness instead.
* **Unevaluable** controls — RA-7 "Risk Response" and IR-5 "Incident
  Monitoring" — describe an organizational process a package scan cannot
  observe in either direction, so they are never asserted from finding data.

Reference: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.constants import AI_PACKAGES as _AI_PACKAGES
from agent_bom.constants import high_risk_severities
from agent_bom.evidence.control_modes import finding_taggable_controls
from agent_bom.risk_analyzer import ToolCapability, classify_mcp_tool

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius

_HIGH_RISK = high_risk_severities()

# ─── Catalog ──────────────────────────────────────────────────────────────────

NIST_800_53: dict[str, str] = {
    # Risk Assessment
    "RA-5": "Vulnerability Monitoring and Scanning",
    "RA-7": "Risk Response",
    # System and Information Integrity
    "SI-2": "Flaw Remediation",
    "SI-3": "Malicious Code Protection",
    "SI-4": "System Monitoring",
    "SI-5": "Security Alerts, Advisories, and Directives",
    "SI-7": "Software, Firmware, and Information Integrity",
    "SI-10": "Information Input Validation",
    "SI-16": "Memory Protection",
    # Supply Chain Risk Management
    "SR-3": "Supply Chain Controls and Processes",
    "SR-4": "Provenance",
    "SR-5": "Acquisition Strategies, Tools, and Methods",
    "SR-11": "Component Authenticity",
    # Access Control
    "AC-3": "Access Enforcement",
    "AC-6": "Least Privilege",
    # Configuration Management
    "CM-6": "Configuration Settings",
    "CM-7": "Least Functionality",
    "CM-8": "System Component Inventory",
    # Identification and Authentication
    "IA-5": "Authenticator Management",
    "IA-7": "Cryptographic Module Authentication",
    # System and Communications Protection
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-12": "Cryptographic Key Establishment and Management",
    "SC-13": "Cryptographic Protection",
    "SC-17": "Public Key Infrastructure Certificates",
    "SC-28": "Protection of Information at Rest",
    # Audit and Accountability
    "AU-2": "Event Logging",
    "AU-6": "Audit Record Review, Analysis, and Reporting",
    # Incident Response
    "IR-5": "Incident Monitoring",
    "IR-6": "Incident Reporting",
}


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted NIST 800-53 Rev 5 control IDs applicable to this blast radius.

    Rules:
    - SI-2:  Always — flaw remediation applies to every CVE.
    - SR-3:  Always — supply chain controls (dependency CVE).
    - SI-4:  HIGH+ severity or >1 agent — system monitoring.
    - SI-5:  KEV — security alert/advisory applies.
    - IR-6:  KEV — incident reporting required.
    - AC-3:  Credentials exposed — access enforcement.
    - AC-6:  Credentials exposed — least privilege concern.
    - IA-5:  Credentials exposed — authenticator management.
    - AC-6:  EXECUTE tools + credentials — least privilege violation.
    - SC-28: READ tools + credentials — data-at-rest protection.
    - SR-4:  AI package — provenance tracking.
    - SR-11: AI package — component authenticity.
    - SI-2:  Fixable vulnerability — flaw remediation (already universal).
    - CM-6:  Fixable vulnerability — configuration settings.
    - CWE-based: lookup from CWE_COMPLIANCE_MAP["nist_800_53"].
    """
    tags: set[str] = {
        "SI-2",  # always — flaw remediation
        "SR-3",  # always — supply chain controls
    }

    is_high = br.vulnerability.severity in _HIGH_RISK

    has_exec = False
    has_read = False
    for tool in br.exposed_tools:
        caps = classify_mcp_tool(tool)
        if ToolCapability.EXECUTE in caps:
            has_exec = True
        if ToolCapability.READ in caps:
            has_read = True

    is_ai_pkg = br.package.name.lower() in _AI_PACKAGES

    # SI-4 — system monitoring for high-severity or multi-agent
    if is_high or len(br.affected_agents) > 1:
        tags.add("SI-4")

    # SI-5 — security alerts for actively exploited vulns (KEV)
    if br.vulnerability.is_kev:
        tags.add("SI-5")

    # IR-6 — incident reporting for actively exploited vulns (KEV)
    if br.vulnerability.is_kev:
        tags.add("IR-6")

    # AC-3 — access enforcement (credentials exposed)
    if br.exposed_credentials:
        tags.add("AC-3")

    # AC-6 — least privilege (credentials exposed)
    if br.exposed_credentials:
        tags.add("AC-6")

    # IA-5 — authenticator management (credentials exposed)
    if br.exposed_credentials:
        tags.add("IA-5")

    # AC-6 — least privilege violation (EXECUTE tools + credentials)
    if has_exec and br.exposed_credentials:
        tags.add("AC-6")  # already added above, but explicit

    # SC-28 — data-at-rest protection (READ tools + credentials)
    if has_read and br.exposed_credentials:
        tags.add("SC-28")

    # SR-4 — provenance tracking for AI packages
    if is_ai_pkg:
        tags.add("SR-4")

    # SR-11 — component authenticity for AI packages
    if is_ai_pkg:
        tags.add("SR-11")

    # CM-6 — configuration settings (fixable vulnerability)
    if br.vulnerability.fixed_version:
        tags.add("CM-6")

    # CWE-based compliance tagging
    if br.vulnerability.cwe_ids:
        from agent_bom.framework_mapping import controls_for_cwes

        tags.update(controls_for_cwes(br.vulnerability.cwe_ids, "nist_800_53"))

    return sorted(finding_taggable_controls("nist_800_53_tags", tags))


def nist_800_53_label(code: str) -> str:
    """Return human-readable label, e.g. 'RA-5 Vulnerability Monitoring and Scanning'."""
    name = NIST_800_53.get(code, "Unknown")
    return f"{code} {name}"


def nist_800_53_labels(codes: list[str]) -> list[str]:
    """Return human-readable labels for a list of NIST 800-53 control codes."""
    return [nist_800_53_label(c) for c in codes]
