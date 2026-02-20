"""NIST AI Risk Management Framework (AI RMF 1.0) — map findings to subcategories.

Maps agent-bom blast radius findings to the NIST AI RMF four-function model
(Govern, Map, Measure, Manage). Every finding gets at minimum MAP-3.5 (supply
chain risk) and GOVERN-1.7 (third-party component risk) since any package CVE
in an AI agent dependency tree triggers both subcategories.

Reference: https://www.nist.gov/artificial-intelligence/ai-risk-management-framework
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.models import Severity

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius


# ─── Catalog ──────────────────────────────────────────────────────────────────

NIST_AI_RMF: dict[str, str] = {
    # GOVERN — Governance structures for managing AI risk
    "GOVERN-1.5": "Ongoing monitoring mechanisms for AI risk",
    "GOVERN-1.7": "Third-party AI component risk processes",
    "GOVERN-6.1": "Assessment policies for third-party AI entities",
    "GOVERN-6.2": "Contingency plans for third-party AI failures",
    # MAP — Context and risk identification
    "MAP-1.6": "System dependencies and external interfaces mapped",
    "MAP-3.5": "AI supply chain risks assessed",
    "MAP-5.2": "AI deployment impact practices identified",
    # MEASURE — Risk assessment and analysis
    "MEASURE-2.5": "AI system security testing conducted",
    "MEASURE-2.6": "AI system results validated",
    "MEASURE-2.9": "Effectiveness of risk mitigations assessed",
    # MANAGE — Risk treatment and response
    "MANAGE-1.3": "Responses to identified AI risks documented",
    "MANAGE-2.2": "Anomalous event detection and response",
    "MANAGE-2.4": "Risk treatments including remediation applied",
    "MANAGE-4.1": "Post-deployment monitoring plans implemented",
}

# AI/ML framework packages — vulnerabilities here map to security testing subcategories
_AI_PACKAGES: frozenset[str] = frozenset({
    "torch", "torchvision", "torchaudio",
    "transformers", "diffusers", "tokenizers",
    "langchain", "langchain-core", "langchain-community",
    "langchain-openai", "langchain-anthropic",
    "openai", "anthropic", "google-generativeai",
    "crewai", "autogen", "pyautogen",
    "haystack", "haystack-ai",
    "llama-index", "llama-cpp-python",
    "dspy-ai", "guidance",
    "semantic-kernel",
    "pydantic-ai",
})

# Tool name keywords that suggest shell/exec capability
_EXEC_KEYWORDS: frozenset[str] = frozenset({
    "exec", "shell", "run", "bash", "cmd", "eval",
    "spawn", "popen", "terminal", "subprocess", "command",
    "execute", "script", "deploy",
})

# Tool name keywords that suggest data access / retrieval
_DATA_KEYWORDS: frozenset[str] = frozenset({
    "read", "file", "resource", "retrieve", "fetch",
    "load", "get_file", "read_file", "open", "download",
    "query", "search", "database", "db", "sql",
})

# Severity levels considered high-risk
_HIGH_RISK: frozenset[Severity] = frozenset({
    Severity.CRITICAL,
    Severity.HIGH,
})


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted NIST AI RMF subcategory IDs applicable to this blast radius.

    Rules:
    - GOVERN-1.7: Always — any CVE in an AI agent triggers third-party risk processes.
    - MAP-3.5:    Always — any CVE is a supply chain risk.
    - GOVERN-6.1: Shell/exec tools reachable → third-party entity assessment needed.
    - GOVERN-6.2: AI framework + credentials + HIGH+ → contingency planning.
    - MAP-1.6:    >3 tools reachable → system interfaces need mapping.
    - MAP-5.2:    Data/file access tools reachable → deployment impact assessment.
    - MEASURE-2.5: AI framework package with HIGH+ CVE → security testing needed.
    - MEASURE-2.9: Vulnerability has a fix → mitigation effectiveness assessment.
    - MANAGE-1.3:  KEV finding → documented risk response required.
    - MANAGE-2.2:  Credentials exposed → anomalous event detection needed.
    - MANAGE-2.4:  AI framework + credentials + HIGH+ → remediation required.
    - MANAGE-4.1:  Credentials exposed + tools → post-deployment monitoring.
    """
    tags: set[str] = {
        "GOVERN-1.7",  # always — third-party AI component risk
        "MAP-3.5",     # always — supply chain risk assessed
    }

    has_exec_tools = False
    has_data_tools = False

    for tool in br.exposed_tools:
        name_lower = tool.name.lower()
        desc_lower = (tool.description or "").lower()
        combined = name_lower + " " + desc_lower

        if any(kw in combined for kw in _EXEC_KEYWORDS):
            has_exec_tools = True
        if any(kw in combined for kw in _DATA_KEYWORDS):
            has_data_tools = True

    # GOVERN-6.1 — third-party entity assessment (shell/exec tools)
    if has_exec_tools:
        tags.add("GOVERN-6.1")

    # MAP-1.6 — system dependencies and interfaces mapped (broad tool surface)
    if len(br.exposed_tools) > 3:
        tags.add("MAP-1.6")

    # MAP-5.2 — deployment impact practices (data access tools)
    if has_data_tools:
        tags.add("MAP-5.2")

    # MANAGE-2.2 — anomalous event detection (credentials exposed)
    if br.exposed_credentials:
        tags.add("MANAGE-2.2")

    # MANAGE-4.1 — post-deployment monitoring (credentials + tools)
    if br.exposed_credentials and br.exposed_tools:
        tags.add("MANAGE-4.1")

    is_ai_pkg = br.package.name.lower() in _AI_PACKAGES
    is_high = br.vulnerability.severity in _HIGH_RISK

    # MEASURE-2.5 — security testing (AI framework + HIGH+ CVE)
    if is_ai_pkg and is_high:
        tags.add("MEASURE-2.5")

    # MEASURE-2.9 — mitigation effectiveness (fix available)
    if br.vulnerability.fixed_version:
        tags.add("MEASURE-2.9")

    # GOVERN-6.2 — contingency plans (AI + creds + HIGH+)
    if is_ai_pkg and br.exposed_credentials and is_high:
        tags.add("GOVERN-6.2")

    # MANAGE-2.4 — risk treatment and remediation (AI + creds + HIGH+)
    if is_ai_pkg and br.exposed_credentials and is_high:
        tags.add("MANAGE-2.4")

    # MANAGE-1.3 — documented risk response (KEV)
    if br.vulnerability.is_kev:
        tags.add("MANAGE-1.3")

    return sorted(tags)


def nist_label(subcategory_id: str) -> str:
    """Return human-readable label, e.g. 'MAP-3.5 AI supply chain risks assessed'."""
    name = NIST_AI_RMF.get(subcategory_id, "Unknown")
    return f"{subcategory_id} {name}"


def nist_labels(subcategory_ids: list[str]) -> list[str]:
    """Return human-readable labels for a list of NIST AI RMF subcategory IDs."""
    return [nist_label(s) for s in subcategory_ids]
