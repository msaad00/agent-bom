"""OWASP Top 10 for LLM Applications — tag blast radius findings.

Maps agent-bom findings to the OWASP Top 10 for Large Language Model
Applications, 2025 edition. Every identifier here and in the CWE table
(``constants.CWE_COMPLIANCE_MAP``) uses 2025 numbering; the 2023 list
assigned different meanings to LLM02-LLM10.

Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.constants import (
    TRAINING_DATA_PACKAGES as _TRAINING_DATA_PACKAGES,
)
from agent_bom.constants import (
    VECTOR_STORE_PACKAGES as _VECTOR_STORE_PACKAGES,
)
from agent_bom.constants import (
    high_risk_severities,
)
from agent_bom.risk_analyzer import ToolCapability, classify_mcp_tool

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius


# ─── Catalog ──────────────────────────────────────────────────────────────────

OWASP_LLM_TOP10: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

_HIGH_RISK_SEVERITIES = high_risk_severities()


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius) -> list[str]:
    """Return sorted OWASP LLM Top 10 (2025) codes applicable to this blast radius.

    Rules applied:
    - LLM03 Supply Chain: always — the finding is a vulnerable third-party
      package reachable from an agent.
    - LLM02 Sensitive Information Disclosure: credential env vars are exposed,
      or a reachable tool can READ data the model may then disclose.
    - LLM05 Improper Output Handling: a reachable tool has EXECUTE capability,
      so model output flows into a command/code sink.
    - LLM06 Excessive Agency: server exposes >5 tools AND severity is HIGH+.
    - LLM04 Data and Model Poisoning: the package handles training data.
    - LLM08 Vector and Embedding Weaknesses: the package is a vector store.
    """
    tags: set[str] = {"LLM03"}

    if br.exposed_credentials:
        tags.add("LLM02")

    for tool in br.exposed_tools:
        caps = classify_mcp_tool(tool)
        if ToolCapability.EXECUTE in caps:
            tags.add("LLM05")
        if ToolCapability.READ in caps:
            tags.add("LLM02")

    if len(br.exposed_tools) > 5 and br.vulnerability.severity in _HIGH_RISK_SEVERITIES:
        tags.add("LLM06")

    package_name = br.package.name.lower()
    if package_name in _TRAINING_DATA_PACKAGES:
        tags.add("LLM04")
    if package_name in _VECTOR_STORE_PACKAGES:
        tags.add("LLM08")

    # CWE-based compliance tagging (applies to all vulns with CWE data)
    if br.vulnerability.cwe_ids:
        from agent_bom.framework_mapping import controls_for_cwes

        tags.update(controls_for_cwes(br.vulnerability.cwe_ids, "owasp_llm"))

    return sorted(tags)


def owasp_label(code: str) -> str:
    """Return human-readable label for an OWASP code, e.g. 'LLM03 Supply Chain'."""
    name = OWASP_LLM_TOP10.get(code, "Unknown")
    return f"{code} {name}"


def owasp_labels(codes: list[str]) -> list[str]:
    """Return human-readable labels for a list of OWASP codes."""
    return [owasp_label(c) for c in codes]
