"""ISO/IEC 27001:2022 Annex A — map findings to information security controls.

Maps agent-bom blast radius findings to ISO 27001:2022 Annex A controls
relevant to software supply chain security.  Every finding triggers at
minimum A.8.8 (technical vulnerability management) since any CVE in an
AI agent dependency tree requires vulnerability management.

Reference: https://www.iso.org/standard/27001
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

ISO_27001: dict[str, str] = {
    # A.5 — Organizational controls
    "A.5.19": "Information security in supplier relationships",
    "A.5.20": "Addressing information security within supplier agreements",
    "A.5.21": "Managing information security in the ICT supply chain",
    "A.5.23": "Information security for use of cloud services",
    "A.5.28": "Collection of evidence",
    # A.8 — Technological controls
    "A.8.8": "Management of technical vulnerabilities",
    "A.8.9": "Configuration management",
    "A.8.24": "Use of cryptography",
    "A.8.28": "Secure coding",
}


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted ISO 27001:2022 Annex A control IDs applicable to this blast radius.

    Rules:
    - A.5.21: Always — ICT supply chain management (any third-party CVE).
    - A.8.8:  Always — technical vulnerability management.
    - A.5.19: Always — supplier relationship security.
    - A.5.20: HIGH+ severity (supplier agreement gaps).
    - A.5.23: Cloud-related package or multiple agents (cloud service security).
    - A.5.28: KEV vulnerability (evidence collection for incident).
    - A.8.9:  Credentials exposed (configuration management concern).
    - A.8.24: Credentials exposed + EXECUTE tools (cryptographic protection needed).
    - A.8.28: Fixable vulnerability (secure coding remediation).
    """
    tags: set[str] = {
        "A.5.19",  # always — supplier relationship security
        "A.5.21",  # always — ICT supply chain management
        "A.8.8",  # always — vulnerability management
    }

    is_high = br.vulnerability.severity in _HIGH_RISK

    has_exec = False
    for tool in br.exposed_tools:
        caps = classify_tool(tool.name, tool.description)
        if ToolCapability.EXECUTE in caps:
            has_exec = True

    # A.5.20 — supplier agreements: HIGH+ severity indicates agreement gaps
    if is_high:
        tags.add("A.5.20")

    # A.5.23 — cloud services: multiple agents or AI framework (likely cloud-hosted)
    if len(br.affected_agents) > 1 or br.package.name.lower() in _AI_PACKAGES:
        tags.add("A.5.23")

    # A.5.28 — evidence collection for KEV (active exploitation)
    if br.vulnerability.is_kev:
        tags.add("A.5.28")

    # A.8.9 — configuration management: credentials exposed
    if br.exposed_credentials:
        tags.add("A.8.9")

    # A.8.24 — cryptography: credentials + exec tools (need encrypted channels)
    if br.exposed_credentials and has_exec:
        tags.add("A.8.24")

    # A.8.28 — secure coding: fixable vulnerability
    if br.vulnerability.fixed_version:
        tags.add("A.8.28")

    return sorted(tags)


def iso_27001_label(code: str) -> str:
    """Return human-readable label, e.g. 'A.8.8 Management of technical vulnerabilities'."""
    name = ISO_27001.get(code, "Unknown")
    return f"{code} {name}"


def iso_27001_labels(codes: list[str]) -> list[str]:
    """Return human-readable labels for a list of ISO 27001 control codes."""
    return [iso_27001_label(c) for c in codes]
