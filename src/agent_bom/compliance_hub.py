"""Compliance Hub — context-aware framework selection (#1044 PR A).

The hub answers a single question that every ingestion path needs to make
the same way: *given a finding, which compliance frameworks apply?*

Without this, every adapter (SARIF, CycloneDX, native scanner, external
imports) re-implements the mapping ad hoc — leading to the same finding
landing under different framework sets depending on which entry point
loaded it. The hub centralises the selection so the answer is one function
call regardless of source.

The framework slug vocabulary and the source/asset/finding-type selection
table now live in :mod:`agent_bom.framework_mapping` — the unified mapping
layer that is the single source of truth for "which framework controls does
this signal evidence". The hub re-exports the selection API for backward
compatibility and adds :func:`apply_hub_classification`, which projects that
selection onto a ``Finding``'s ``applicable_frameworks``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.compliance_coverage import normalize_framework_slug

# The framework vocabulary + selection engine were consolidated into
# ``framework_mapping``. Re-exported here so existing callers importing these
# names from ``compliance_hub`` keep working unchanged.
from agent_bom.framework_mapping import (
    ALL_FRAMEWORKS,
    FRAMEWORK_ATLAS,
    FRAMEWORK_ATTACK,
    FRAMEWORK_CIS,
    FRAMEWORK_CMMC,
    FRAMEWORK_EU_AI_ACT,
    FRAMEWORK_FEDRAMP,
    FRAMEWORK_ISO_27001,
    FRAMEWORK_NIST_800_53,
    FRAMEWORK_NIST_AI_RMF,
    FRAMEWORK_NIST_CSF,
    FRAMEWORK_OWASP_AGENTIC,
    FRAMEWORK_OWASP_LLM,
    FRAMEWORK_OWASP_MCP,
    FRAMEWORK_PCI_DSS,
    FRAMEWORK_SOC2,
    is_framework_relevant,
    select_frameworks,
)

if TYPE_CHECKING:
    from agent_bom.finding import Finding

__all__ = [
    "ALL_FRAMEWORKS",
    "FRAMEWORK_ATLAS",
    "FRAMEWORK_ATTACK",
    "FRAMEWORK_CIS",
    "FRAMEWORK_CMMC",
    "FRAMEWORK_EU_AI_ACT",
    "FRAMEWORK_FEDRAMP",
    "FRAMEWORK_ISO_27001",
    "FRAMEWORK_NIST_800_53",
    "FRAMEWORK_NIST_AI_RMF",
    "FRAMEWORK_NIST_CSF",
    "FRAMEWORK_OWASP_AGENTIC",
    "FRAMEWORK_OWASP_LLM",
    "FRAMEWORK_OWASP_MCP",
    "FRAMEWORK_PCI_DSS",
    "FRAMEWORK_SOC2",
    "select_frameworks",
    "is_framework_relevant",
    "apply_hub_classification",
]


def apply_hub_classification(finding: "Finding", *, include_gov: bool = False) -> "Finding":
    """Populate `finding.applicable_frameworks` using the hub selection table.

    Idempotent and additive: existing entries are preserved, the hub-derived
    slugs are merged in (deduped, canonical order). Used by every finding
    generator and ingestion adapter so a finding's framework classification
    is consistent regardless of which entry point produced it.

    Returns the same finding for fluent chaining.
    """
    selected = select_frameworks(
        finding.source,
        asset_type=finding.asset.asset_type,
        finding_type=finding.finding_type,
        include_gov=include_gov,
    )
    seen: set[str] = set()
    normalized_frameworks: list[str] = []
    for slug in finding.applicable_frameworks:
        canonical = normalize_framework_slug(str(slug))
        if canonical not in seen:
            seen.add(canonical)
            normalized_frameworks.append(canonical)
    finding.applicable_frameworks = normalized_frameworks
    for slug in selected:
        if slug not in seen:
            finding.applicable_frameworks.append(slug)
            seen.add(slug)
    # Re-order to canonical so consumers can hash the list reliably.
    finding.applicable_frameworks = [slug for slug in ALL_FRAMEWORKS if slug in seen] + [
        slug for slug in finding.applicable_frameworks if slug not in ALL_FRAMEWORKS
    ]
    return finding
