"""Compliance Hub framework-selection matrix (#1044 PR A).

This test file is the executable version of the table in issue #1044:
each (FindingSource, asset_type, finding_type) row maps to an expected
set of frameworks that apply. If a future PR adds a new source or
re-classifies an existing one, these tests force the change to be
deliberate — the matrix is the contract.

Two-way invariants we lock in here:

1. **Inclusion** — for every documented (source × asset) pairing, the
   expected frameworks must be selected.
2. **Exclusion** — the AI-side frameworks (OWASP LLM / MCP / Agentic /
   ATLAS / NIST AI RMF / EU AI Act) must NOT show up on pure-cloud or
   pure-container findings, and vice versa. Scope discipline matters
   because compliance auditors will read the dashboard literally.

The hub is meant to be the *only* place that answers "which frameworks
apply to this finding"; ingestion paths in PR B will call into it.
"""

from __future__ import annotations

import pytest

from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS
from agent_bom.compliance_hub import (
    FRAMEWORK_ATLAS,
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
from agent_bom.finding import FindingSource, FindingType

_AI_FRAMEWORK_SET = {
    FRAMEWORK_OWASP_LLM,
    FRAMEWORK_OWASP_MCP,
    FRAMEWORK_OWASP_AGENTIC,
    FRAMEWORK_ATLAS,
    FRAMEWORK_NIST_AI_RMF,
    FRAMEWORK_EU_AI_ACT,
}


# ─── Table from #1044 — each row is one source × asset → expected frameworks ──


@pytest.mark.parametrize(
    "source,asset_type,expected_subset",
    [
        # AI / agent / MCP findings → all six AI frameworks
        (FindingSource.MCP_SCAN, "agent", _AI_FRAMEWORK_SET),
        (FindingSource.MCP_SCAN, "mcp_server", _AI_FRAMEWORK_SET),
        (FindingSource.MCP_SCAN, "tool", _AI_FRAMEWORK_SET),
        (FindingSource.SKILL, "skill", _AI_FRAMEWORK_SET),
        # Runtime proxy → AI frameworks (LLM + Agentic + ATLAS minimum)
        (FindingSource.PROXY, None, {FRAMEWORK_OWASP_LLM, FRAMEWORK_OWASP_AGENTIC, FRAMEWORK_ATLAS}),
        # Browser extension → LLM + ATLAS
        (FindingSource.BROWSER_EXT, None, {FRAMEWORK_OWASP_LLM, FRAMEWORK_ATLAS}),
        # Container image → CIS + NIST CSF + PCI + SOC2
        (
            FindingSource.CONTAINER,
            "container",
            {FRAMEWORK_CIS, FRAMEWORK_NIST_CSF, FRAMEWORK_PCI_DSS, FRAMEWORK_SOC2},
        ),
        # Cloud CIS posture → CIS + SOC2 + ISO + NIST 800-53
        (
            FindingSource.CLOUD_CIS,
            "cloud_resource",
            {FRAMEWORK_CIS, FRAMEWORK_SOC2, FRAMEWORK_ISO_27001, FRAMEWORK_NIST_800_53},
        ),
        # SBOM / supply chain → NIST CSF + SOC2 + PCI
        (FindingSource.SBOM, "package", {FRAMEWORK_NIST_CSF, FRAMEWORK_SOC2, FRAMEWORK_PCI_DSS}),
        # SAST / code → NIST CSF + SOC2 + PCI
        (FindingSource.SAST, None, {FRAMEWORK_NIST_CSF, FRAMEWORK_SOC2, FRAMEWORK_PCI_DSS}),
        # Filesystem → CIS + SOC2
        (FindingSource.FILESYSTEM, None, {FRAMEWORK_CIS, FRAMEWORK_SOC2}),
    ],
)
def test_source_baseline_includes_expected_frameworks(source: FindingSource, asset_type: str | None, expected_subset: set[str]) -> None:
    selected = set(select_frameworks(source, asset_type=asset_type))
    missing = expected_subset - selected
    assert not missing, (
        f"source={source.value} asset_type={asset_type!r} should select "
        f"{sorted(expected_subset)}; missing {sorted(missing)} from {sorted(selected)}"
    )


# ─── Scope discipline — AI frameworks must not leak onto pure-infra findings ──


@pytest.mark.parametrize(
    "source,asset_type,banned",
    [
        # Container/cloud findings must NOT carry AI framework tags
        (FindingSource.CONTAINER, "container", _AI_FRAMEWORK_SET),
        (FindingSource.CLOUD_CIS, "cloud_resource", _AI_FRAMEWORK_SET),
        (FindingSource.FILESYSTEM, None, _AI_FRAMEWORK_SET),
    ],
)
def test_ai_frameworks_do_not_leak_to_infra_findings(source: FindingSource, asset_type: str | None, banned: set[str]) -> None:
    selected = set(select_frameworks(source, asset_type=asset_type))
    leaked = banned & selected
    assert not leaked, (
        f"source={source.value} asset_type={asset_type!r} must not select AI frameworks {sorted(banned)}; leaked: {sorted(leaked)}"
    )


# ─── Finding-type refinements — same source, different finding shape ──────────


def test_credential_exposure_pulls_in_enterprise_audit_frameworks() -> None:
    """A leaked credential is a SOC 2 / ISO 27001 / NIST CSF event no
    matter where it surfaced. The hub must add those even when the source
    baseline wouldn't."""
    selected = set(
        select_frameworks(
            FindingSource.MCP_SCAN,
            asset_type="mcp_server",
            finding_type=FindingType.CREDENTIAL_EXPOSURE,
        )
    )
    for framework in (FRAMEWORK_NIST_CSF, FRAMEWORK_ISO_27001, FRAMEWORK_SOC2):
        assert framework in selected, f"CREDENTIAL_EXPOSURE on MCP_SCAN must include {framework}; got {sorted(selected)}"


def test_injection_finding_pulls_in_ai_frameworks_even_from_neutral_source() -> None:
    """An INJECTION finding ingested via SAST/EXTERNAL must still light up
    the AI framework set — the finding shape, not the source, drives the
    classification here."""
    selected = set(
        select_frameworks(
            FindingSource.SAST,
            finding_type=FindingType.INJECTION,
        )
    )
    for framework in _AI_FRAMEWORK_SET:
        assert framework in selected, f"INJECTION must surface {framework} regardless of source; got {sorted(selected)}"


def test_cis_fail_pulls_in_cis_even_when_source_does_not() -> None:
    selected = set(select_frameworks(FindingSource.SAST, finding_type=FindingType.CIS_FAIL))
    assert FRAMEWORK_CIS in selected


# ─── External imports — auto-detect / catch-all ─────────────────────────────


def test_external_source_selects_every_framework() -> None:
    """SARIF / CycloneDX / CSV imports may carry findings whose source
    can't be inferred. The hub returns every framework so the importer
    can prune based on actual finding metadata in PR B."""
    selected = set(select_frameworks(FindingSource.EXTERNAL))
    expected = {meta.slug for meta in TAG_MAPPED_FRAMEWORKS} - {"aisvs"}  # benchmark slug, not tag-mapped
    missing = expected - selected
    assert not missing, f"EXTERNAL must offer every tag-mapped framework; missing {sorted(missing)}"


# ─── Government overlay — opt-in ─────────────────────────────────────────────


def test_gov_overlay_off_by_default() -> None:
    selected = set(select_frameworks(FindingSource.CLOUD_CIS, asset_type="cloud_resource"))
    assert FRAMEWORK_FEDRAMP not in selected
    assert FRAMEWORK_CMMC not in selected


def test_gov_overlay_on_demand() -> None:
    selected = set(
        select_frameworks(
            FindingSource.CLOUD_CIS,
            asset_type="cloud_resource",
            include_gov=True,
        )
    )
    assert FRAMEWORK_FEDRAMP in selected
    assert FRAMEWORK_CMMC in selected
    assert FRAMEWORK_NIST_800_53 in selected


# ─── Stable ordering — the hub must return frameworks in canonical order ─────


def test_select_frameworks_returns_stable_canonical_order() -> None:
    """Two calls with the same inputs return the same list. This matters
    for downstream consumers that hash / cache the framework set."""
    a = select_frameworks(FindingSource.MCP_SCAN, asset_type="mcp_server")
    b = select_frameworks(FindingSource.MCP_SCAN, asset_type="mcp_server")
    assert a == b, "select_frameworks must be deterministic"


def test_is_framework_relevant_matches_select_frameworks() -> None:
    """The convenience wrapper must agree with the full selector."""
    selected = select_frameworks(FindingSource.MCP_SCAN, asset_type="mcp_server")
    for slug in selected:
        assert is_framework_relevant(slug, FindingSource.MCP_SCAN, asset_type="mcp_server")
    assert not is_framework_relevant(FRAMEWORK_PCI_DSS, FindingSource.MCP_SCAN, asset_type="mcp_server")


# ─── Slug parity — every selectable slug must exist in the coverage catalog ──


def test_every_selected_slug_resolves_in_compliance_coverage() -> None:
    """If select_frameworks returns a slug, the dashboard / report API
    must be able to render it. This catches drift where the hub references
    a framework that isn't in TAG_MAPPED_FRAMEWORKS."""
    coverage_slugs = {meta.slug for meta in TAG_MAPPED_FRAMEWORKS}
    # Walk every plausible source and asset combination
    for source in FindingSource:
        for asset_type in (None, "mcp_server", "agent", "tool", "container", "cloud_resource", "package"):
            for slug in select_frameworks(source, asset_type=asset_type, include_gov=True):
                assert slug in coverage_slugs, (
                    f"Hub returned slug {slug!r} for source={source.value} / asset={asset_type!r} "
                    f"but it isn't registered in compliance_coverage.TAG_MAPPED_FRAMEWORKS"
                )
