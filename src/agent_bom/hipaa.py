"""HIPAA Security Rule — map findings to applicable safeguard sections.

Maps agent-bom blast radius findings to the HIPAA Security Rule
(45 CFR 164.308-312) sections relevant to software supply chain security.
HIPAA is mandatory for healthcare/health-tech organizations (covered entities
and business associates) handling electronic protected health information (ePHI).

Every finding triggers at minimum 164.308(a)(1)(ii)(A) (risk analysis) since
any CVE in a dependency constitutes an identified risk to ePHI confidentiality,
integrity, or availability.

References:
    - HIPAA Security Rule: https://www.hhs.gov/sites/default/files/ocr/privacy/hipaa/administrative/securityrule/techsafeguards.pdf
    - 2024 NPRM factsheet: https://www.hhs.gov/hipaa/for-professionals/security/hipaa-security-rule-nprm/factsheet/index.html
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

HIPAA_SAFEGUARDS: dict[str, str] = {
    # 164.308 — Administrative Safeguards
    "164.308(a)(1)(ii)(A)": "Risk analysis",
    "164.308(a)(1)(ii)(B)": "Risk management",
    "164.308(a)(1)(ii)(D)": "Information system activity review",
    "164.308(a)(3)(ii)(A)": "Authorization and/or supervision",
    "164.308(a)(4)(ii)(B)": "Access authorization",
    "164.308(a)(5)(ii)(A)": "Security reminders",
    "164.308(a)(5)(ii)(B)": "Protection from malicious software",
    "164.308(a)(6)(ii)": "Response and reporting",
    "164.308(a)(7)(ii)(A)": "Data backup plan",
    "164.308(a)(8)": "Evaluation",
    # 164.310 — Physical Safeguards (subset relevant to software)
    "164.310(d)(1)": "Device and media controls",
    # 164.312 — Technical Safeguards
    "164.312(a)(1)": "Access control",
    "164.312(a)(2)(iv)": "Encryption and decryption",
    "164.312(b)": "Audit controls",
    "164.312(c)(1)": "Integrity",
    "164.312(c)(2)": "Mechanism to authenticate ePHI",
    "164.312(d)": "Person or entity authentication",
    "164.312(e)(1)": "Transmission security",
    "164.312(e)(2)(ii)": "Encryption",
}

# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted HIPAA Security Rule section references applicable to this blast radius.

    Rules:
    - 164.308(a)(1)(ii)(A): Always — risk analysis (any CVE is an identified risk).
    - 164.308(a)(1)(ii)(B): Always — risk management (remediation required).
    - 164.308(a)(8): Always — evaluation (vulnerability scanning is evaluation).
    - 164.308(a)(1)(ii)(D): >1 affected agent (activity review across systems).
    - 164.308(a)(3)(ii)(A): EXECUTE-capable tools (authorization/supervision needed).
    - 164.308(a)(4)(ii)(B): Credentials exposed (access authorization concern).
    - 164.308(a)(5)(ii)(A): KEV vulnerability (security reminder/advisory).
    - 164.308(a)(5)(ii)(B): HIGH+ severity (malicious software protection).
    - 164.308(a)(6)(ii): KEV vulnerability (incident response and reporting).
    - 164.308(a)(7)(ii)(A): HIGH+ with credentials (data backup urgency).
    - 164.310(d)(1): AI framework package (device/media controls for AI models).
    - 164.312(a)(1): Credentials exposed (access control breach).
    - 164.312(a)(2)(iv): Credentials exposed (encryption of data at rest).
    - 164.312(b): Always — audit controls (vulnerability audit trail).
    - 164.312(c)(1): HIGH+ severity (integrity of ePHI at risk).
    - 164.312(c)(2): Credentials + EXECUTE tools (ePHI authentication concern).
    - 164.312(d): Credentials + multi-agent (entity authentication needed).
    - 164.312(e)(1): >1 affected agent with tools (transmission security).
    - 164.312(e)(2)(ii): Credentials exposed (encryption in transit needed).
    """
    tags: set[str] = {
        "164.308(a)(1)(ii)(A)",  # always — risk analysis
        "164.308(a)(1)(ii)(B)",  # always — risk management
        "164.308(a)(8)",         # always — evaluation
        "164.312(b)",            # always — audit controls
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

    # 164.308(a)(1)(ii)(D) — activity review: multi-agent exposure
    if multi_agent:
        tags.add("164.308(a)(1)(ii)(D)")

    # 164.308(a)(3)(ii)(A) — authorization/supervision: EXECUTE-capable tools
    if has_exec:
        tags.add("164.308(a)(3)(ii)(A)")

    # 164.308(a)(4)(ii)(B) — access authorization: credentials exposed
    if has_creds:
        tags.add("164.308(a)(4)(ii)(B)")

    # 164.308(a)(5)(ii)(A) — security reminders: KEV (active exploitation)
    if br.vulnerability.is_kev:
        tags.add("164.308(a)(5)(ii)(A)")

    # 164.308(a)(5)(ii)(B) — malicious software protection: HIGH+ severity
    if is_high:
        tags.add("164.308(a)(5)(ii)(B)")

    # 164.308(a)(6)(ii) — incident response: KEV (active exploitation)
    if br.vulnerability.is_kev:
        tags.add("164.308(a)(6)(ii)")

    # 164.308(a)(7)(ii)(A) — data backup: HIGH+ with credentials
    if is_high and has_creds:
        tags.add("164.308(a)(7)(ii)(A)")

    # 164.310(d)(1) — device/media controls: AI framework package
    if is_ai_pkg:
        tags.add("164.310(d)(1)")

    # 164.312(a)(1) — access control: credentials exposed
    if has_creds:
        tags.add("164.312(a)(1)")

    # 164.312(a)(2)(iv) — encryption at rest: credentials exposed
    if has_creds:
        tags.add("164.312(a)(2)(iv)")

    # 164.312(c)(1) — integrity: HIGH+ severity
    if is_high:
        tags.add("164.312(c)(1)")

    # 164.312(c)(2) — ePHI authentication: credentials + EXECUTE
    if has_creds and has_exec:
        tags.add("164.312(c)(2)")

    # 164.312(d) — entity authentication: credentials + multi-agent
    if has_creds and multi_agent:
        tags.add("164.312(d)")

    # 164.312(e)(1) — transmission security: multi-agent with tools
    if multi_agent and br.exposed_tools:
        tags.add("164.312(e)(1)")

    # 164.312(e)(2)(ii) — encryption in transit: credentials exposed
    if has_creds:
        tags.add("164.312(e)(2)(ii)")

    # CWE-based tagging for SAST findings
    if br.package.ecosystem == "sast" and br.vulnerability.cwe_ids:
        from agent_bom.constants import SAST_CWE_MAP

        for cwe in br.vulnerability.cwe_ids:
            for tag in SAST_CWE_MAP.get(cwe.upper(), {}).get("hipaa", []):
                tags.add(tag)

    return sorted(tags)


def hipaa_label(code: str) -> str:
    """Return human-readable label, e.g. '164.308(a)(1)(ii)(A) Risk analysis'."""
    name = HIPAA_SAFEGUARDS.get(code, "Unknown")
    return f"{code} {name}"


def hipaa_labels(codes: list[str]) -> list[str]:
    """Return human-readable labels for a list of HIPAA section references."""
    return [hipaa_label(c) for c in codes]
