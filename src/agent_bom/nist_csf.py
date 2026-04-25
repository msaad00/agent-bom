"""NIST Cybersecurity Framework (CSF) 2.0 — map findings to functions and categories.

Maps agent-bom blast radius findings to the NIST CSF 2.0 six-function model
(Govern, Identify, Protect, Detect, Respond, Recover).  Every finding triggers
at minimum ID.RA-01 (vulnerability identification) and GV.SC-05 (supply chain
risk management) since any package CVE in an AI agent dependency tree
represents both.

Reference: https://www.nist.gov/cyberframework
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

NIST_CSF: dict[str, str] = {
    # GOVERN — Organizational context and risk strategy
    "GV.SC-05": "Cyber supply chain risk management requirements established",
    "GV.SC-07": "Supplier risks identified, recorded, and mitigated",
    # IDENTIFY — Asset and risk identification
    "ID.AM-05": "Assets prioritized based on classification and criticality",
    "ID.RA-01": "Vulnerabilities in assets are identified",
    "ID.RA-02": "Cyber threat intelligence received from information sharing forums",
    "ID.RA-05": "Threats, vulnerabilities, likelihoods, and impacts used to determine risk",
    # PROTECT — Safeguards
    "PR.AA-01": "Identities and credentials managed for authorized users and services",
    "PR.AA-03": "Users, services, and hardware are authenticated",
    "PR.DS-01": "Data-at-rest is protected",
    "PR.DS-02": "Data-in-transit is protected",
    # DETECT — Anomaly and event detection
    "DE.CM-01": "Networks and network services are monitored",
    "DE.CM-09": "Computing hardware and software are monitored for vulnerabilities",
    # RESPOND — Incident response
    "RS.AN-03": "Analysis is performed to determine what has taken place",
    "RS.MI-02": "Incidents are contained and mitigated",
}


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted NIST CSF 2.0 category IDs applicable to this blast radius.

    Rules:
    - GV.SC-05: Always — any CVE in a dependency is a supply chain risk.
    - ID.RA-01: Always — vulnerability identified in an asset.
    - ID.RA-02: KEV/EPSS enriched (threat intelligence applied).
    - ID.RA-05: HIGH+ severity (risk assessment needed).
    - ID.AM-05: AI framework package (critical asset classification).
    - GV.SC-07: Supplier risk recorded (always with vuln).
    - PR.AA-01: Credentials exposed (identity management concern).
    - PR.AA-03: EXECUTE-capable tools (authentication bypass risk).
    - PR.DS-01: READ-capable tools + credentials (data-at-rest risk).
    - PR.DS-02: >3 affected agents (data-in-transit across agents).
    - DE.CM-09: Always — vulnerability monitoring triggered.
    - DE.CM-01: >1 affected agent (network-level monitoring needed).
    - RS.AN-03: Fixable vulnerability (analysis for remediation).
    - RS.MI-02: KEV vulnerability (active exploitation, containment needed).
    """
    tags: set[str] = {
        "GV.SC-05",  # always — supply chain risk
        "GV.SC-07",  # always — supplier risk recorded
        "ID.RA-01",  # always — vulnerability identified
        "DE.CM-09",  # always — vulnerability monitoring
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

    # ID.RA-02 — threat intelligence applied (KEV or EPSS enrichment)
    if br.vulnerability.is_kev or (br.vulnerability.epss_score or 0) > 0:
        tags.add("ID.RA-02")

    # ID.RA-05 — risk assessment for high-severity findings
    if is_high:
        tags.add("ID.RA-05")

    # ID.AM-05 — critical asset classification for AI framework packages
    if is_ai_pkg:
        tags.add("ID.AM-05")

    # PR.AA-01 — credential management concern
    if br.exposed_credentials:
        tags.add("PR.AA-01")

    # PR.AA-03 — authentication bypass via EXECUTE tools
    if has_exec and br.exposed_credentials:
        tags.add("PR.AA-03")

    # PR.DS-01 — data-at-rest exposure via READ tools + credentials
    if has_read and br.exposed_credentials:
        tags.add("PR.DS-01")

    # PR.DS-02 — data-in-transit across multiple agents
    if len(br.affected_agents) > 3:
        tags.add("PR.DS-02")

    # DE.CM-01 — network monitoring needed for multi-agent exposure
    if len(br.affected_agents) > 1:
        tags.add("DE.CM-01")

    # RS.AN-03 — remediation analysis for fixable vulns
    if br.vulnerability.fixed_version:
        tags.add("RS.AN-03")

    # RS.MI-02 — containment for actively exploited vulns
    if br.vulnerability.is_kev:
        tags.add("RS.MI-02")

    # CWE-based compliance tagging (applies to all vulns with CWE data)
    if br.vulnerability.cwe_ids:
        from agent_bom.constants import CWE_COMPLIANCE_MAP

        for cwe in br.vulnerability.cwe_ids:
            for tag in CWE_COMPLIANCE_MAP.get(cwe.upper(), {}).get("nist_csf", []):
                tags.add(tag)

    return sorted(tags)


def nist_csf_label(code: str) -> str:
    """Return human-readable label, e.g. 'ID.RA-01 Vulnerabilities in assets are identified'."""
    name = NIST_CSF.get(code, "Unknown")
    return f"{code} {name}"


def nist_csf_labels(codes: list[str]) -> list[str]:
    """Return human-readable labels for a list of NIST CSF category codes."""
    return [nist_csf_label(c) for c in codes]
