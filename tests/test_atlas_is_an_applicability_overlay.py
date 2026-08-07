"""MITRE ATLAS describes adversary techniques, so it cannot be passed or failed.

The codebase already made this argument for ATT&CK:

    ATT&CK describes adversary behaviour, not controls an estate implements.
    A technique is APPLICABLE or not; it cannot pass or fail, and scoring it
    as a failing control asserted dozens of unevidenced failures per CVE.

ATLAS is the AI counterpart of ATT&CK -- its own registry entry carries
``catalog=ATLAS_TECHNIQUES`` and ``bundled_unit="techniques"`` -- and the
argument transfers verbatim. It was nonetheless scored, and at 65 techniques it
was the single largest scored framework: 27% of the entire scored control
surface (65 of 240) was technique rows, each asserting a failure the estate had
no way to "pass".
"""

from __future__ import annotations

from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS

_BY_SLUG = {metadata.slug: metadata for metadata in TAG_MAPPED_FRAMEWORKS}


def test_atlas_is_not_scored() -> None:
    """The regression: ATLAS must not contribute pass/fail to the score."""
    assert _BY_SLUG["atlas"].scored is False


def test_atlas_and_attack_are_classified_consistently() -> None:
    """Two adversary-technique matrices cannot be scored differently.

    This is the inconsistency that let the bug exist: the same reasoning was
    applied to one MITRE matrix and not its direct counterpart.
    """
    assert _BY_SLUG["atlas"].scored == _BY_SLUG["attack"].scored


def test_every_technique_catalog_is_an_overlay() -> None:
    """A framework measured in "techniques" is describing attacker behaviour.

    Stated structurally so a future technique-based catalog cannot be added as
    a scored framework without this failing first.
    """
    technique_frameworks = [m for m in TAG_MAPPED_FRAMEWORKS if m.bundled_unit == "techniques"]

    assert technique_frameworks, "expected at least one technique catalog"
    assert [m.framework for m in technique_frameworks if m.scored] == []


def test_control_frameworks_remain_scored() -> None:
    """The fix must not quietly unscore real control frameworks.

    Unscoring everything would make the score vacuous rather than accurate.
    """
    for slug in ("owasp-llm", "nist", "nist-800-53", "iso-27001", "soc2", "pci-dss"):
        assert _BY_SLUG[slug].scored is True, slug


def test_overlay_coverage_text_says_it_is_not_scored() -> None:
    """An overlay must announce itself, so a reader never reads it as a score."""
    for metadata in TAG_MAPPED_FRAMEWORKS:
        if not metadata.scored:
            assert "not scored" in metadata.coverage.lower(), metadata.framework
