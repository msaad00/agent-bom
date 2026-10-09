"""EU AI Act — map technical findings to the articles whose requirements they concern.

Maps agent-bom blast radius findings to articles of the EU Artificial
Intelligence Act (Regulation (EU) 2024/1689). A tag means "this technical
evidence is relevant to the requirement in Article N"; it is never a legal
classification of the system. Whether a system is prohibited (Art. 5) or
high-risk (Art. 6) depends on its intended purpose and context of use, which
cannot be inferred from dependencies or tools, so those articles are never
tagged.

Reference: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.risk_analyzer import ToolCapability, classify_mcp_tool

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius


# ─── Catalog ──────────────────────────────────────────────────────────────────

# Article titles as published in Regulation (EU) 2024/1689.
EU_AI_ACT: dict[str, str] = {
    "ART-9": "Risk Management System",
    "ART-10": "Data and Data Governance",
    "ART-12": "Record-Keeping",
    "ART-14": "Human Oversight",
    "ART-15": "Accuracy, Robustness and Cybersecurity",
    "ART-17": "Quality Management System",
}


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted EU AI Act article codes this blast radius is evidence for.

    Rules:
    - ART-9:  Always — an identified risk feeds the risk management system.
    - ART-15: Always — a vulnerable dependency or exposed credential is a
              cybersecurity/robustness weakness.
    - ART-14: A reachable tool can EXECUTE, so the agent can act without a
              human in the loop.
    - ART-12: The weakness undermines event logging (log injection,
              insufficient logging CWEs).
    - ART-17: A fixed version exists (remediation through the QMS).

    ART-10 is evidenced only by dataset findings (``parsers.compliance_tags``),
    never by a package CVE.
    """
    tags: set[str] = {"ART-9", "ART-15"}

    for tool in br.exposed_tools:
        if ToolCapability.EXECUTE in classify_mcp_tool(tool):
            tags.add("ART-14")
            break

    if br.vulnerability.fixed_version:
        tags.add("ART-17")

    if br.vulnerability.cwe_ids:
        from agent_bom.framework_mapping import controls_for_cwes

        tags.update(controls_for_cwes(br.vulnerability.cwe_ids, "eu_ai_act"))

    return sorted(tags)


def eu_ai_act_label(code: str) -> str:
    """Return human-readable label, e.g. 'ART-15 Accuracy, Robustness and Cybersecurity'."""
    name = EU_AI_ACT.get(code, "Unknown")
    return f"{code} {name}"


def eu_ai_act_labels(codes: list[str]) -> list[str]:
    """Return human-readable labels for a list of EU AI Act article codes."""
    return [eu_ai_act_label(c) for c in codes]
