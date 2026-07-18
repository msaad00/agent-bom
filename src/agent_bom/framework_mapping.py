"""Unified framework-mapping layer — the single source of truth for resolving a
finding/check signal to the compliance-framework controls it evidences.

Historically this resolution ran through three parallel code paths:

  1. **CWE -> per-framework control IDs.** Every blast-radius tagger
     (``cis_controls``, ``nist_800_53``, ``iso_27001``, ``owasp``, ``soc2``,
     ``nist_csf``, ``pci_dss``) and ``vuln_compliance`` inlined the identical
     ``CWE_COMPLIANCE_MAP.get(cwe).get(framework)`` lookup.
  2. **CVE-intrinsic tagging** built on the same CWE table.
  3. **Finding source/asset/finding-type -> framework slug fan-out**
     (``compliance_hub.select_frameworks``).

They now all resolve here, so "which framework controls does this signal
evidence?" has one answer regardless of caller.

DATA PROVENANCE — VENDOR-ASSERTED. Every mapping in this layer is agent-bom's
own asserted judgment of which control a given check/finding evidences. It is
**not** an official crosswalk published by a framework authority, and it is
**not** a control-to-control crosswalk between frameworks. A signal maps to the
controls it evidences *within each framework independently*; cross-framework
attribution emerges only because a shared check happens to evidence controls in
several frameworks. Consumers and UI copy must label these as vendor-asserted,
never "official".

PR2 CATALOG. ``FRAMEWORK_CONTROL_CATALOG`` is the registry of provenanced
authoritative catalogs: ``framework -> {control_id -> ControlSpec(title,
evidencing_checks, ...)}``. It is populated from the vendored data in
``agent_bom.framework_catalog``:

* ``nist-800-53`` carries the full NIST SP 800-53 Rev 5 catalog — control IDs
  and **authoritative public-domain titles** (NIST is a U.S. Government work,
  CC0 1.0), ``reference_only=False``.
* ``iso-27001`` / ``soc2`` / ``cis`` are **reference-only** stubs
  (``reference_only=True``): the control **ID** is the fact, but the ``title``
  is ``None`` or agent-bom's own short descriptor — never the copyrighted
  official ISO / AICPA / CIS title, none of which are vendored anywhere in this
  tree.

``control_spec()`` is the read seam; ``evidencing_checks`` stays empty here
(PR3 curates check -> control). ``nist_to_iso()`` exposes NIST's own official
SP 800-53 Rev 5 -> ISO/IEC 27001:2022 crosswalk (ISO referenced by ID only).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

# CWE_COMPLIANCE_MAP physically lives in ``constants`` (a dependency-free leaf
# module). This layer owns the *resolution API* over it and re-exports it so
# callers depend on ``framework_mapping`` rather than the raw table — leaving
# PR2 free to relocate the data behind this seam without touching callers.
from agent_bom import framework_catalog
from agent_bom.constants import CWE_COMPLIANCE_MAP
from agent_bom.finding import FindingSource, FindingType

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = [
    "CWE_COMPLIANCE_MAP",
    "controls_for_cwe",
    "controls_for_cwes",
    "FRAMEWORK_CONTROL_CATALOG",
    "ControlSpec",
    "control_spec",
    "nist_to_iso",
    "select_frameworks",
    "is_framework_relevant",
    "ALL_FRAMEWORKS",
]


# ─── CWE -> per-framework control resolution (paths 1 + 2) ───────────────────


def controls_for_cwe(cwe: str, framework_key: str, *, normalize: bool = True) -> list[str]:
    """Return the control IDs a single CWE evidences under one framework.

    Args:
        cwe: A CWE identifier, e.g. ``"CWE-89"``.
        framework_key: The framework key used inside ``CWE_COMPLIANCE_MAP``
            (``"cis"``, ``"nist_800_53"``, ``"iso_27001"``, ``"owasp_llm"``,
            ``"soc2"``, ``"nist_csf"``, ``"pci_dss"``).
        normalize: Upper-case the CWE id before lookup. The blast-radius taggers
            normalize (``cwe.upper()``); ``vuln_compliance`` looks up the raw id,
            so it passes ``normalize=False``. Preserved verbatim so the
            consolidation is behavior-identical.

    Returns:
        The control-ID list (empty for an unknown CWE or framework key). The
        returned list is the mapping's own list; callers must not mutate it.
    """
    key = cwe.upper() if normalize else cwe
    return CWE_COMPLIANCE_MAP.get(key, {}).get(framework_key, [])


def controls_for_cwes(cwe_ids: Iterable[str], framework_key: str, *, normalize: bool = True) -> list[str]:
    """Resolve a collection of CWEs to one framework's controls, deduped.

    First-seen order is preserved (matching ``vuln_compliance``'s
    order-preserving append); the blast-radius taggers fold the result into a
    set and sort, so order is immaterial to them.
    """
    out: list[str] = []
    for cwe in cwe_ids:
        for control in controls_for_cwe(cwe, framework_key, normalize=normalize):
            if control not in out:
                out.append(control)
    return out


# ─── PR2 seam: provenanced authoritative catalog registry ────────────────────


@dataclass(frozen=True)
class ControlSpec:
    """A single control's metadata plus the checks that evidence it.

    ``title`` carries a control name only when we may lawfully store one: for
    ``nist-800-53`` it is NIST's authoritative public-domain title; for the
    reference-only frameworks (``iso-27001`` / ``soc2`` / ``cis``) it is ``None``
    or agent-bom's own short descriptor — never the copyrighted official title.
    ``reference_only`` flags the latter, where only the control **ID** is a
    vendorable fact.

    VENDOR-ASSERTED (see module docstring): ``evidencing_checks`` records which
    agent-bom checks map to this control, not an authority-published crosswalk.
    """

    control_id: str
    title: str | None
    evidencing_checks: tuple[str, ...] = field(default_factory=tuple)
    reference_only: bool = False


# framework slug -> {control_id -> ControlSpec}. Populated at import time from the
# vendored, provenance-tagged data in ``agent_bom.framework_catalog`` (see the
# ``_build_framework_control_catalog`` call at the end of this module).
FRAMEWORK_CONTROL_CATALOG: dict[str, dict[str, ControlSpec]] = {}


def control_spec(framework_key: str, control_id: str) -> ControlSpec | None:
    """Return the catalog entry for a control, or None when uncatalogued."""
    return FRAMEWORK_CONTROL_CATALOG.get(framework_key, {}).get(control_id)


def nist_to_iso(control_id: str) -> list[str]:
    """Return the ISO/IEC 27001:2022 Annex A control IDs NIST's official
    SP 800-53 Rev 5 crosswalk maps ``control_id`` to (identifiers only).

    This is the one authoritative cross-framework mapping we vendor; ISO control
    titles are copyrighted and are not stored. Empty list when NIST publishes no
    ISO mapping for the control.
    """
    return framework_catalog.iso_controls_for_nist(control_id)


# ─── Framework slug vocabulary ───────────────────────────────────────────────
# Aligned with ``agent_bom.compliance_coverage.TAG_MAPPED_FRAMEWORKS`` slugs.
# The slug is what flows through the API surface; keep the two in sync.

FRAMEWORK_OWASP_LLM = "owasp-llm"
FRAMEWORK_OWASP_MCP = "owasp-mcp"
FRAMEWORK_OWASP_AGENTIC = "owasp-agentic"
FRAMEWORK_ATLAS = "atlas"
FRAMEWORK_ATTACK = "attack"
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
    FRAMEWORK_ATTACK,
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
    FRAMEWORK_ATTACK,
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

# External SARIF/CSV/JSON imports without AI asset signals should not inherit
# the full AI framework set — those slugs are added via asset_type / finding_type
# refinements (agent, mcp_server, INJECTION, etc.).
_EXTERNAL_BASELINE: tuple[str, ...] = (
    FRAMEWORK_NIST_CSF,
    FRAMEWORK_SOC2,
    FRAMEWORK_ISO_27001,
    FRAMEWORK_CIS,
    FRAMEWORK_PCI_DSS,
)


# ─── Source -> framework selection table (path 3, the source of truth) ───────
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
    # A CIS Foundations Benchmark check (CIS-2.1.1 …) authoritatively asserts the
    # CIS control it failed and nothing more. There is no authoritative
    # CIS-Foundations → SOC2/ISO-27001/NIST-800-53 crosswalk in the repo, so the
    # prior wholesale fan-out (_CLOUD_POSTURE_FRAMEWORKS) over-claimed
    # cross-framework coverage. Assert only CIS; a specific SOC2/ISO/NIST claim
    # must wait on an authoritative crosswalk (tracked follow-up).
    FindingSource.CLOUD_CIS: (FRAMEWORK_CIS,),
    # Vendor security best practices (e.g. Databricks) are explicitly NOT official
    # CIS/SOC2/ISO/NIST controls, and there is no authoritative crosswalk from
    # them to those frameworks in the repo. Claiming SOC2/ISO-27001/NIST-800-53
    # coverage (the prior wholesale fan-out) over-claims, so assert no official
    # framework — the vendor-best-practice designation lives in the finding type
    # (CLOUD_BEST_PRACTICE_*), source, title, and evidence, not in
    # applicable_frameworks (which holds only official framework slugs). A
    # finding-shape refinement (e.g. CREDENTIAL_EXPOSURE) can still add frameworks
    # on its own authority; the source baseline just asserts nothing.
    FindingSource.CLOUD_SECURITY: (),
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
    FindingSource.EXTERNAL: _EXTERNAL_BASELINE,
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
    FindingType.CIS_ERROR: (FRAMEWORK_CIS,),
    FindingType.CLOUD_BEST_PRACTICE_FAIL: (),
    FindingType.CLOUD_BEST_PRACTICE_ERROR: (),
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

    # Cloud-posture sources already carry an authoritative source baseline; the
    # broad cloud_resource asset addition (_CLOUD_POSTURE_FRAMEWORKS) would
    # re-introduce the SOC2/ISO/NIST-800-53 over-claim they were narrowed away
    # from, so skip it for those sources.
    _cloud_posture_sources = {FindingSource.CLOUD_SECURITY, FindingSource.CLOUD_CIS}
    if asset_type and not (source in _cloud_posture_sources and asset_type == "cloud_resource"):
        selected.update(_ASSET_TYPE_ADDITIONS.get(asset_type, ()))

    if finding_type:
        selected.update(_FINDING_TYPE_ADDITIONS.get(finding_type, ()))

    if include_gov:
        selected.update(_GOV_FRAMEWORKS)

    return [f for f in ALL_FRAMEWORKS if f in selected]


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


# ─── Populate the provenanced control catalog (import-time, once) ─────────────


def _build_framework_control_catalog() -> None:
    """Fill ``FRAMEWORK_CONTROL_CATALOG`` from the vendored framework data.

    NIST 800-53 is stored in full (public-domain titles). ISO 27001, SOC 2, and
    CIS are reference-only: the ID is the fact, the title is None or agent-bom's
    own descriptor. No copyrighted ISO/AICPA/CIS title is ever placed here.
    """
    # Own-worded descriptors for the reference-only frameworks (never the
    # official copyrighted titles). Imported locally to keep this resolution
    # layer's public import surface minimal.
    from agent_bom.cis_controls import CIS_CONTROLS
    from agent_bom.iso_27001 import ISO_27001
    from agent_bom.soc2 import SOC2_TSC

    FRAMEWORK_CONTROL_CATALOG[FRAMEWORK_NIST_800_53] = {
        control_id: ControlSpec(control_id=control_id, title=spec["title"])
        for control_id, spec in framework_catalog.nist_controls().items()
    }

    # ISO 27001 (reference-only): every Annex A control NIST's crosswalk cites,
    # plus the IDs our own taggers use. Title = our own descriptor if we have
    # one, else None — the official ISO title is never stored.
    crosswalk = framework_catalog.nist_to_iso_crosswalk()
    iso_ids = {iso for ids in crosswalk.values() for iso in ids} | set(ISO_27001)
    FRAMEWORK_CONTROL_CATALOG[FRAMEWORK_ISO_27001] = {
        control_id: ControlSpec(control_id, ISO_27001.get(control_id), reference_only=True) for control_id in sorted(iso_ids)
    }

    FRAMEWORK_CONTROL_CATALOG[FRAMEWORK_SOC2] = {
        control_id: ControlSpec(control_id, SOC2_TSC[control_id], reference_only=True) for control_id in SOC2_TSC
    }
    FRAMEWORK_CONTROL_CATALOG[FRAMEWORK_CIS] = {
        control_id: ControlSpec(control_id, CIS_CONTROLS[control_id], reference_only=True) for control_id in CIS_CONTROLS
    }


_build_framework_control_catalog()
