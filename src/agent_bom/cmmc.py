"""CMMC 2.0 Level 2 — map findings to applicable practices.

Maps agent-bom blast radius findings to Cybersecurity Maturity Model
Certification (CMMC) 2.0 Level 2 practices.  CMMC Level 2 aligns to
NIST SP 800-171 Rev 2, which derives from NIST SP 800-53 moderate baseline.

CMMC 2.0 is required for Department of Defense (DoD) contractors handling
Controlled Unclassified Information (CUI) — affecting 300,000+ organizations.

Every finding triggers at minimum RA.L2-3.11.2 (vulnerability scanning) and
SI.L2-3.14.1 (flaw remediation) since any CVE in a dependency requires both.

References:
    - CMMC to NIST crosswalk: https://dodcio.defense.gov/Portals/0/Documents/CMMC/CMMC-AlignmentNIST-Standards.pdf
    - NIST 800-171 Rev 3: https://csrc.nist.gov/pubs/sp/800/171/r3/final
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

CMMC_PRACTICES: dict[str, str] = {
    # RA — Risk Assessment (NIST 800-171: 3.11)
    "RA.L2-3.11.2": "Vulnerability scanning",
    "RA.L2-3.11.3": "Remediate vulnerabilities",
    # SI — System and Information Integrity (NIST 800-171: 3.14)
    "SI.L2-3.14.1": "Flaw remediation",
    "SI.L2-3.14.2": "Malicious code protection",
    "SI.L2-3.14.3": "Security alerts, advisories, and directives",
    "SI.L2-3.14.6": "Monitor communications for attacks",
    "SI.L2-3.14.7": "Identify unauthorized use",
    # SC — System and Communications Protection (NIST 800-171: 3.13)
    "SC.L2-3.13.1": "Monitor communications at boundaries",
    "SC.L2-3.13.2": "Employ architectural designs and techniques for security",
    "SC.L2-3.13.5": "Implement subnetworks for publicly accessible components",
    # CM — Configuration Management (NIST 800-171: 3.4)
    "CM.L2-3.4.1": "Establish and maintain baseline configurations",
    "CM.L2-3.4.2": "Establish and enforce security configuration settings",
    "CM.L2-3.4.3": "Track, review, and control changes",
    # AC — Access Control (NIST 800-171: 3.1)
    "AC.L2-3.1.1": "Limit system access to authorized users",
    "AC.L2-3.1.2": "Limit system access to authorized transactions and functions",
    "AC.L2-3.1.7": "Prevent non-privileged users from executing privileged functions",
    # IA — Identification and Authentication (NIST 800-171: 3.5)
    "IA.L2-3.5.3": "Use multi-factor authentication for local and network access",
}

# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted CMMC 2.0 Level 2 practice IDs applicable to this blast radius.

    Rules:
    - RA.L2-3.11.2: Always — vulnerability scanning performed.
    - SI.L2-3.14.1: Always — flaw remediation required for any CVE.
    - CM.L2-3.4.3: Always — track/control changes (software inventory).
    - RA.L2-3.11.3: Fixable vulnerability (remediation available).
    - SI.L2-3.14.2: HIGH+ severity (malicious code protection).
    - SI.L2-3.14.3: KEV vulnerability (security advisory/directive).
    - SI.L2-3.14.6: >1 affected agent (monitor multi-agent comms).
    - SI.L2-3.14.7: AI framework package (identify unauthorized use).
    - SC.L2-3.13.1: EXECUTE-capable tools (boundary monitoring needed).
    - SC.L2-3.13.2: Credentials + EXECUTE tools (architectural concern).
    - SC.L2-3.13.5: >1 affected agent with exposed tools (subnetwork isolation).
    - CM.L2-3.4.1: AI framework package (baseline config for AI components).
    - CM.L2-3.4.2: HIGH+ severity with credentials (enforce security configs).
    - AC.L2-3.1.1: Credentials exposed (access control breach).
    - AC.L2-3.1.2: EXECUTE-capable tools (unauthorized function execution).
    - AC.L2-3.1.7: EXECUTE tools + credentials (privilege escalation risk).
    - IA.L2-3.5.3: Credentials + multi-agent (authentication concern).
    """
    tags: set[str] = {
        "RA.L2-3.11.2",  # always — vulnerability scanning
        "SI.L2-3.14.1",  # always — flaw remediation
        "CM.L2-3.4.3",  # always — track/control changes
    }

    is_high = br.vulnerability.severity in _HIGH_RISK
    has_creds = bool(br.exposed_credentials)
    is_ai_pkg = br.package.name.lower() in _AI_PACKAGES
    multi_agent = len(br.affected_agents) > 1

    has_exec = False
    for tool in br.exposed_tools:
        caps = classify_tool(tool.name, tool.description)
        if ToolCapability.EXECUTE in caps:
            has_exec = True

    # RA.L2-3.11.3 — remediate vulnerabilities: fix available
    if br.vulnerability.fixed_version:
        tags.add("RA.L2-3.11.3")

    # SI.L2-3.14.2 — malicious code protection: HIGH+ severity
    if is_high:
        tags.add("SI.L2-3.14.2")

    # SI.L2-3.14.3 — security alerts/directives: KEV (active exploitation)
    if br.vulnerability.is_kev:
        tags.add("SI.L2-3.14.3")

    # SI.L2-3.14.6 — monitor comms for attacks: multi-agent exposure
    if multi_agent:
        tags.add("SI.L2-3.14.6")

    # SI.L2-3.14.7 — identify unauthorized use: AI framework package
    if is_ai_pkg:
        tags.add("SI.L2-3.14.7")

    # SC.L2-3.13.1 — monitor at boundaries: EXECUTE-capable tools
    if has_exec:
        tags.add("SC.L2-3.13.1")

    # SC.L2-3.13.2 — architectural security: credentials + EXECUTE
    if has_creds and has_exec:
        tags.add("SC.L2-3.13.2")

    # SC.L2-3.13.5 — subnetwork isolation: multi-agent with exposed tools
    if multi_agent and br.exposed_tools:
        tags.add("SC.L2-3.13.5")

    # CM.L2-3.4.1 — baseline configurations: AI framework package
    if is_ai_pkg:
        tags.add("CM.L2-3.4.1")

    # CM.L2-3.4.2 — enforce security configs: HIGH+ with credentials
    if is_high and has_creds:
        tags.add("CM.L2-3.4.2")

    # AC.L2-3.1.1 — limit access: credentials exposed
    if has_creds:
        tags.add("AC.L2-3.1.1")

    # AC.L2-3.1.2 — limit functions: EXECUTE-capable tools
    if has_exec:
        tags.add("AC.L2-3.1.2")

    # AC.L2-3.1.7 — prevent privilege escalation: EXECUTE + credentials
    if has_exec and has_creds:
        tags.add("AC.L2-3.1.7")

    # IA.L2-3.5.3 — multi-factor auth: credentials + multi-agent
    if has_creds and multi_agent:
        tags.add("IA.L2-3.5.3")

    # CWE-based tagging for SAST findings
    if br.package.ecosystem == "sast" and br.vulnerability.cwe_ids:
        from agent_bom.constants import SAST_CWE_MAP

        for cwe in br.vulnerability.cwe_ids:
            for tag in SAST_CWE_MAP.get(cwe.upper(), {}).get("cmmc", []):
                tags.add(tag)

    return sorted(tags)


def cmmc_label(code: str) -> str:
    """Return human-readable label, e.g. 'RA.L2-3.11.2 Vulnerability scanning'."""
    name = CMMC_PRACTICES.get(code, "Unknown")
    return f"{code} {name}"


def cmmc_labels(codes: list[str]) -> list[str]:
    """Return human-readable labels for a list of CMMC practice IDs."""
    return [cmmc_label(c) for c in codes]
