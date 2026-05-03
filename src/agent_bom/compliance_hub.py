"""Compliance Hub — context-aware framework selection (#1044 PR A).

The hub answers a single question that every ingestion path needs to make
the same way: *given a finding, which compliance frameworks apply?*

Without this, every adapter (SARIF, CycloneDX, native scanner, external
imports) re-implements the mapping ad hoc — leading to the same finding
landing under different framework sets depending on which entry point
loaded it. The hub centralises the selection table from issue #1044 so
the answer is one function call regardless of source.

This is PR A (foundation): pure mapping engine + test matrix. PR B wires
the engine into ingestion adapters; PR C exposes hub aggregation
endpoints + dashboard surface; PR D locks in cross-format invariants.

The table below is the source of truth. Adding a new finding source or
asset type means adding a row here, not editing every adapter.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.finding import FindingSource, FindingType

if TYPE_CHECKING:
    from agent_bom.finding import Finding

# ─── Framework slugs ─────────────────────────────────────────────────────────
# Aligned with `agent_bom.compliance_coverage.TAG_MAPPED_FRAMEWORKS` slugs.
# Keep this list in sync — the slug is what flows through the API surface.

FRAMEWORK_OWASP_LLM = "owasp-llm"
FRAMEWORK_OWASP_MCP = "owasp-mcp"
FRAMEWORK_OWASP_AGENTIC = "owasp-agentic"
FRAMEWORK_ATLAS = "atlas"
FRAMEWORK_NIST_AI_RMF = "nist"
FRAMEWORK_NIST_CSF = "nist-csf"
FRAMEWORK_NIST_800_53 = "nist-800-53"
FRAMEWORK_FEDRAMP = "fedramp"
FRAMEWORK_EU_AI_ACT = "eu-ai-act"
FRAMEWORK_ISO_27001 = "iso-27001"
FRAMEWORK_SOC2 = "soc2"
FRAMEWORK_CIS = "cis"
FRAMEWORK_CMMC = "cmmc"
FRAMEWORK_PCI_DSS = "pci-dss"

ALL_FRAMEWORKS: tuple[str, ...] = (
    FRAMEWORK_OWASP_LLM,
    FRAMEWORK_OWASP_MCP,
    FRAMEWORK_OWASP_AGENTIC,
    FRAMEWORK_ATLAS,
    FRAMEWORK_NIST_AI_RMF,
    FRAMEWORK_NIST_CSF,
    FRAMEWORK_NIST_800_53,
    FRAMEWORK_FEDRAMP,
    FRAMEWORK_EU_AI_ACT,
    FRAMEWORK_ISO_27001,
    FRAMEWORK_SOC2,
    FRAMEWORK_CIS,
    FRAMEWORK_CMMC,
    FRAMEWORK_PCI_DSS,
)


_AI_FRAMEWORKS: tuple[str, ...] = (
    FRAMEWORK_OWASP_LLM,
    FRAMEWORK_OWASP_MCP,
    FRAMEWORK_OWASP_AGENTIC,
    FRAMEWORK_ATLAS,
    FRAMEWORK_NIST_AI_RMF,
    FRAMEWORK_EU_AI_ACT,
)

_ENTERPRISE_FRAMEWORKS: tuple[str, ...] = (
    FRAMEWORK_NIST_CSF,
    FRAMEWORK_ISO_27001,
    FRAMEWORK_SOC2,
)

_GOV_FRAMEWORKS: tuple[str, ...] = (
    FRAMEWORK_NIST_800_53,
    FRAMEWORK_FEDRAMP,
    FRAMEWORK_CMMC,
)

_CONTAINER_FRAMEWORKS: tuple[str, ...] = (
    FRAMEWORK_CIS,
    FRAMEWORK_NIST_CSF,
    FRAMEWORK_PCI_DSS,
    FRAMEWORK_SOC2,
)

_CLOUD_POSTURE_FRAMEWORKS: tuple[str, ...] = (
    FRAMEWORK_CIS,
    FRAMEWORK_SOC2,
    FRAMEWORK_ISO_27001,
    FRAMEWORK_NIST_800_53,
)


# ─── Source → framework selection table (the source of truth) ───────────────
# Issue #1044 specifies this mapping. Each source carries a baseline list of
# frameworks that always apply; asset type and finding type can refine.

_SOURCE_BASELINE: dict[FindingSource, tuple[str, ...]] = {
    FindingSource.MCP_SCAN: _AI_FRAMEWORKS,
    FindingSource.SKILL: _AI_FRAMEWORKS,
    FindingSource.PROXY: (
        FRAMEWORK_OWASP_LLM,
        FRAMEWORK_OWASP_AGENTIC,
        FRAMEWORK_ATLAS,
    ),
    FindingSource.BROWSER_EXT: (
        FRAMEWORK_OWASP_LLM,
        FRAMEWORK_ATLAS,
    ),
    FindingSource.CONTAINER: _CONTAINER_FRAMEWORKS,
    FindingSource.CLOUD_CIS: _CLOUD_POSTURE_FRAMEWORKS,
    FindingSource.SBOM: (
        FRAMEWORK_NIST_CSF,
        FRAMEWORK_SOC2,
        FRAMEWORK_PCI_DSS,
    ),
    FindingSource.SAST: (
        FRAMEWORK_NIST_CSF,
        FRAMEWORK_SOC2,
        FRAMEWORK_PCI_DSS,
    ),
    FindingSource.FILESYSTEM: (
        FRAMEWORK_CIS,
        FRAMEWORK_SOC2,
    ),
    FindingSource.EXTERNAL: ALL_FRAMEWORKS,
}


# Asset-type refinements: when the source baseline is broad, asset shape
# narrows it. These are *additive* — they don't shrink the baseline.
_ASSET_TYPE_ADDITIONS: dict[str, tuple[str, ...]] = {
    "mcp_server": _AI_FRAMEWORKS,
    "agent": _AI_FRAMEWORKS,
    "tool": _AI_FRAMEWORKS,
    "skill": _AI_FRAMEWORKS,
    "container": _CONTAINER_FRAMEWORKS,
    "cloud_resource": _CLOUD_POSTURE_FRAMEWORKS,
    "iac_resource": (FRAMEWORK_CIS, FRAMEWORK_NIST_800_53, FRAMEWORK_FEDRAMP),
}


# Finding-type refinements: a CREDENTIAL_EXPOSURE on any source pulls in
# enterprise auditing frameworks; LICENSE pulls in supply-chain governance.
_FINDING_TYPE_ADDITIONS: dict[FindingType, tuple[str, ...]] = {
    FindingType.CREDENTIAL_EXPOSURE: _ENTERPRISE_FRAMEWORKS,
    FindingType.LICENSE: (FRAMEWORK_NIST_CSF, FRAMEWORK_SOC2),
    FindingType.INJECTION: _AI_FRAMEWORKS,
    FindingType.EXFILTRATION: _AI_FRAMEWORKS + (FRAMEWORK_SOC2,),
    FindingType.CIS_FAIL: (FRAMEWORK_CIS,),
}


def select_frameworks(
    source: FindingSource,
    asset_type: str | None = None,
    finding_type: FindingType | None = None,
    *,
    include_gov: bool = False,
) -> list[str]:
    """Return the list of framework slugs that apply to a finding context.

    Args:
        source: Which scanner / ingestion path produced the finding.
        asset_type: The Asset.asset_type (e.g. "mcp_server", "container",
            "cloud_resource", "package", "agent"). Optional but recommended.
        finding_type: The FindingType (e.g. CREDENTIAL_EXPOSURE, INJECTION).
            Adds finding-shape-specific frameworks on top of the source
            baseline.
        include_gov: When True, layer FedRAMP / NIST 800-53 / CMMC on top.
            Off by default because most tenants don't operate under those
            programs; the dashboard / API can opt in per tenant.

    Returns:
        Deduplicated list of framework slugs in stable order, drawn from
        ALL_FRAMEWORKS so callers can match against
        compliance_coverage.TAG_MAPPED_FRAMEWORKS.
    """
    selected: set[str] = set()

    selected.update(_SOURCE_BASELINE.get(source, ()))

    if asset_type:
        selected.update(_ASSET_TYPE_ADDITIONS.get(asset_type, ()))

    if finding_type:
        selected.update(_FINDING_TYPE_ADDITIONS.get(finding_type, ()))

    if include_gov:
        selected.update(_GOV_FRAMEWORKS)

    return [f for f in ALL_FRAMEWORKS if f in selected]


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
    seen = set(finding.applicable_frameworks)
    for slug in selected:
        if slug not in seen:
            finding.applicable_frameworks.append(slug)
            seen.add(slug)
    # Re-order to canonical so consumers can hash the list reliably.
    finding.applicable_frameworks = [slug for slug in ALL_FRAMEWORKS if slug in seen] + [
        slug for slug in finding.applicable_frameworks if slug not in ALL_FRAMEWORKS
    ]
    return finding


def is_framework_relevant(
    framework_slug: str,
    source: FindingSource,
    asset_type: str | None = None,
    finding_type: FindingType | None = None,
    *,
    include_gov: bool = False,
) -> bool:
    """Return True if `framework_slug` applies to this finding context.

    Convenience wrapper for filtering — equivalent to checking membership
    in `select_frameworks(...)` but cheaper for single-framework checks.
    """
    return framework_slug in select_frameworks(
        source,
        asset_type,
        finding_type,
        include_gov=include_gov,
    )
