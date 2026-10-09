"""NIST AI Risk Management Framework (AI RMF 1.0) — map findings to subcategories.

Maps agent-bom blast radius findings to the NIST AI RMF four-function model
(Govern, Map, Measure, Manage). A finding in an AI-relevant context gets
GOVERN-6.1 (third-party risk policies) and MAP-4.1 (risks of components,
including third-party software). Subcategory IDs follow the AI RMF 1.0 core
(NIST AI 100-1, Tables 1-4).

Reference: https://www.nist.gov/artificial-intelligence/ai-risk-management-framework
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.constants import AI_PACKAGES as _AI_PACKAGES
from agent_bom.constants import high_risk_severities
from agent_bom.risk_analyzer import ToolCapability, classify_mcp_tool

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius


# ─── Catalog ──────────────────────────────────────────────────────────────────

NIST_AI_RMF: dict[str, str] = {
    # GOVERN — Governance structures for managing AI risk
    "GOVERN-1.5": "Ongoing monitoring and periodic review of AI risk management",
    "GOVERN-6.1": "Policies address AI risks from third-party entities",
    "GOVERN-6.2": "Contingency processes for third-party data or AI system failures",
    # MAP — Context and risk identification
    "MAP-3.5": "Human oversight processes defined and documented",
    "MAP-4.1": "Technology and legal risks of AI components, including third-party software, mapped",
    "MAP-5.1": "Likelihood and magnitude of identified impacts documented",
    # MEASURE — Risk assessment and analysis
    "MEASURE-2.6": "AI system evaluated regularly for safety risks",
    "MEASURE-2.7": "AI system security and resilience evaluated and documented",
    # MANAGE — Risk treatment and response
    "MANAGE-1.3": "Responses to high-priority AI risks developed, planned, and documented",
    "MANAGE-4.1": "Post-deployment monitoring plans implemented",
}

_HIGH_RISK = high_risk_severities()


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted NIST AI RMF subcategory IDs applicable to this blast radius.

    Rules:
    - GOVERN-6.1 / MAP-4.1: AI framework, agent context, or HIGH+ — a
      third-party component risk to govern and map.
    - MAP-3.5:     EXECUTE-capable tools reachable → human oversight needed.
    - MAP-5.1:     Data/file READ tools reachable → impact must be assessed.
    - MEASURE-2.7: AI framework package with HIGH+ CVE → security evaluation.
    - MANAGE-1.3:  KEV finding or available fix → documented risk response.
    - MANAGE-4.1:  Credentials exposed + tools → post-deployment monitoring.
    - GOVERN-6.2:  AI framework + credentials + HIGH+ → contingency planning.
    """
    tags: set[str] = set()

    is_ai_pkg = br.package.name.lower() in _AI_PACKAGES
    has_agent_context = bool(br.exposed_credentials) or bool(br.exposed_tools)
    is_high = br.vulnerability.severity in _HIGH_RISK

    if is_ai_pkg or has_agent_context or is_high:
        tags.add("GOVERN-6.1")
        tags.add("MAP-4.1")

    has_exec = False
    has_read = False
    for tool in br.exposed_tools:
        caps = classify_mcp_tool(tool)
        if ToolCapability.EXECUTE in caps:
            has_exec = True
        if ToolCapability.READ in caps:
            has_read = True

    if has_exec:
        tags.add("MAP-3.5")

    if has_read:
        tags.add("MAP-5.1")

    if br.exposed_credentials and br.exposed_tools:
        tags.add("MANAGE-4.1")

    if is_ai_pkg and is_high:
        tags.add("MEASURE-2.7")

    if br.vulnerability.fixed_version or br.vulnerability.is_kev:
        tags.add("MANAGE-1.3")

    if is_ai_pkg and br.exposed_credentials and is_high:
        tags.add("GOVERN-6.2")

    return sorted(tags)


def nist_label(subcategory_id: str) -> str:
    """Return human-readable label, e.g. 'MAP-4.1 Technology and legal risks of AI components ...'."""
    name = NIST_AI_RMF.get(subcategory_id, "Unknown")
    return f"{subcategory_id} {name}"


def nist_labels(subcategory_ids: list[str]) -> list[str]:
    """Return human-readable labels for a list of NIST AI RMF subcategory IDs."""
    return [nist_label(s) for s in subcategory_ids]
